/** @file KmDeviceStateApp.c
 *
 *  DXE driver (auto-executed by the DXE dispatcher at every boot):
 *  read -> patch -> write the DeviceInfo unlock flags.
 *  Integrated into Mu-Silicium nuwaPkg (Xiaomi 13 Pro, SM8550).
 *
 *  Path 1 (primary, direct-TA "constant" method):
 *    Qseecom protocol (from stock TzDxe/ScmDxeCompat) -> keymaster TA ->
 *    cmd 514 READ 8K/4K block -> locate "ANDROID-BOOT!" -> set [13]/[14]=1 ->
 *    cmd 515 WRITE back -> verify re-read.
 *
 *  Path 2 (fallback, mimics stock ABL / VbRwStateApp):
 *    QCOM_VERIFIEDBOOT_PROTOCOL.VBRwDeviceState(READ_CONFIG/WRITE_CONFIG).
 *
 *  Evidence-based constants (SM8550/SM8750 firmware + VbRwStateApp binary):
 *    514=0x202 READ_KM_DEVICE_STATE, 515=0x203 WRITE_KM_DEVICE_STATE,
 *    8 KiB block (4 KiB on some newer SoCs), 12-byte {cmd_id,buf_ptr,buf_size},
 *    12-byte response buffer (VerifiedBootDxe passes rbuf_len=12),
 *    magic "ANDROID-BOOT!" with unlock flags at [13]/[14],
 *    VB path buffer 0xD10 (3344) - same as VbRwStateApp.
 *
 *  NOTE: this is an early-DXE driver (depex = Qseecom protocol), so
 *  gST->ConOut may not exist yet. All logging goes through DEBUG (serial);
 *  do NOT use Print() here.
 *
 *  Preconditions:
 *    1. AVB/milestone gate bypassed (no SendMilestone call in your BDS).
 *    2. keymaster TA loadable (QseecomStartApp succeeds).
 *    3. RPMB provisioned, milestone not yet set.
 */

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/EFIQseecom.h>
#include <Protocol/EFIVerifiedBoot.h>

// The QcomPkg DEC declares these GUIDs but no source in this tree defines the
// symbols (TzDxe/VerifiedBootDxe are prebuilt binaries), so define them here
// locally to keep the module self-contained at link time.
EFI_GUID mQcomQseecomProtocolGuid = {
  0xA74862CE, 0x680F, 0x4FE1,
  {0xA3, 0x11, 0xDF, 0x41, 0xF4, 0x03, 0x03, 0x91}
};

EFI_GUID mQcomVerifiedBootProtocolGuid = {
  0x8E5EFF91, 0x21B6, 0x47D3,
  {0xAF, 0x2B, 0xC1, 0x5A, 0x01, 0xE0, 0x20, 0xEC}
};

#define KM_CMD_READ_DEVICE_STATE    514   /* 0x202 */
#define KM_CMD_WRITE_DEVICE_STATE   515   /* 0x203 */

#define KM_BLOCK_8K                  0x2000
#define KM_BLOCK_4K                  0x1000
#define KM_RESP_SIZE                 12    /* VerifiedBootDxe passes 12 */
#define VB_BUF_SIZE                  0xD10 /* 3344: same as VbRwStateApp */

#define DI_MAGIC                     "ANDROID-BOOT!"
#define DI_MAGIC_LEN                 13
#define DI_OFF_UNLOCKED              13
#define DI_OFF_UNLOCK_CRITICAL       14

// 12-byte command structure observed in VerifiedBootDxe:
// {cmd_id, buf_ptr(32-bit), buf_size}. Buffer must be below 4 GB.
#pragma pack(push, 1)
typedef struct {
  UINT32 CmdId;
  UINT32 BufPtr;
  UINT32 BufSize;
} KM_DEVICE_STATE_CMD;
#pragma pack(pop)

// Locate the DeviceInfo structure inside a block by magic scan
// (field offsets vary by SoC/version; the magic does not).
static UINT8 *
FindDeviceInfo (
  IN UINT8 *Block,
  IN UINTN BlockSize
  )
{
  UINTN Idx;
  for (Idx = 0; Idx + DI_MAGIC_LEN <= BlockSize; Idx += 4) {
    if (CompareMem (Block + Idx, DI_MAGIC, DI_MAGIC_LEN) == 0) {
      return Block + Idx;
    }
  }
  return NULL;
}

static EFI_STATUS
SendDeviceStateCmd (
  IN QCOM_QSEECOM_PROTOCOL *Qseecom,
  IN UINT32                AppId,
  IN UINT32                CmdId,
  IN VOID                  *Block,
  IN UINT32                BlockSize
  )
{
  KM_DEVICE_STATE_CMD Cmd;
  UINT32              Resp[KM_RESP_SIZE / sizeof (UINT32)];  /* 12 bytes */

  Cmd.CmdId   = CmdId;
  Cmd.BufPtr  = (UINT32)(UINTN)Block;
  Cmd.BufSize = BlockSize;
  ZeroMem (Resp, sizeof (Resp));

  return Qseecom->QseecomSendCmd (
                   Qseecom,
                   AppId,
                   (UINT8 *)&Cmd,
                   sizeof (Cmd),
                   (UINT8 *)Resp,
                   sizeof (Resp)
                   );
}

// ---------------------------------------------------------------------------
// Path 1: direct keymaster TA via Qseecom protocol (cmd 514/515)
// ---------------------------------------------------------------------------
static EFI_STATUS
UnlockViaQseecom (
  VOID
  )
{
  EFI_STATUS             Status;
  QCOM_QSEECOM_PROTOCOL *Qseecom = NULL;
  UINT32                 AppId   = 0;
  CHAR8                 *TaNames[2];
  UINT32                 BlockSizes[2];
  UINTN                  TaIdx;
  UINTN                  SzIdx;
  UINTN                  PageCount;
  UINT32                 BlockSize;
  EFI_PHYSICAL_ADDRESS   BlockAddr;
  UINT8                 *Block = NULL;
  UINT8                 *Di    = NULL;
  BOOLEAN                MagicFound;

  TaNames[0]    = "keymaster";
  TaNames[1]    = "keymaster64";
  BlockSizes[0] = KM_BLOCK_8K;
  BlockSizes[1] = KM_BLOCK_4K;

  // 1. Qseecom protocol (installed by TzDxe/ScmDxeCompat).
  Status = gBS->LocateProtocol (&mQcomQseecomProtocolGuid, NULL, (VOID **)&Qseecom);
  if (EFI_ERROR (Status) || Qseecom == NULL) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: LocateProtocol(Qseecom) failed: %r\n", Status));
    return Status;
  }

  // 2. Load the keymaster TA ("keymaster" on SM8550/SM8750; "keymaster64" on
  //    some newer SoCs per atlas PoC).
  Status = EFI_NOT_FOUND;
  for (TaIdx = 0; TaIdx < 2 && EFI_ERROR (Status); TaIdx++) {
    Status = Qseecom->QseecomStartApp (Qseecom, TaNames[TaIdx], &AppId);
    if (!EFI_ERROR (Status)) {
      DEBUG ((EFI_D_INFO, "KmDeviceStateApp: TA '%a' AppId = %u\n", TaNames[TaIdx], (UINTN)AppId));
      break;
    }
  }
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: QseecomStartApp(keymaster*) failed: %r\n", Status));
    return Status;
  }

  // 3. READ + patch + WRITE, trying 8 KiB then 4 KiB (block size varies by SoC).
  MagicFound = FALSE;
  for (SzIdx = 0; SzIdx < 2; SzIdx++) {
    BlockSize = BlockSizes[SzIdx];
    PageCount = EFI_SIZE_TO_PAGES (BlockSize);
    BlockAddr = 0xFFFFF000; /* force allocation below 4 GB for 32-bit BufPtr */
    Status = gBS->AllocatePages (
                    AllocateMaxAddress,
                    EfiRuntimeServicesData,
                    PageCount,
                    &BlockAddr
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_WARN, "KmDeviceStateApp: alloc %x failed: %r\n", (UINTN)BlockSize, Status));
      continue;
    }
    Block = (UINT8 *)(UINTN)BlockAddr;
    ZeroMem (Block, BlockSize);

    Status = SendDeviceStateCmd (Qseecom, AppId, KM_CMD_READ_DEVICE_STATE, Block, BlockSize);
    if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_WARN, "KmDeviceStateApp: read cmd 514 (%x block) failed: %r\n", (UINTN)BlockSize, Status));
      gBS->FreePages (BlockAddr, PageCount);
      Block = NULL;
      continue;
    }

    Di = FindDeviceInfo (Block, BlockSize);
    if (Di == NULL) {
      DEBUG ((EFI_D_WARN, "KmDeviceStateApp: magic not found in %x block\n", (UINTN)BlockSize));
      gBS->FreePages (BlockAddr, PageCount);
      Block = NULL;
      continue;
    }

    MagicFound = TRUE;
    break;
  }

  if (!MagicFound || Block == NULL || Di == NULL) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: no readable DeviceInfo block found\n"));
    return EFI_NOT_FOUND;
  }

  DEBUG ((EFI_D_INFO, "KmDeviceStateApp: DeviceInfo @ block+0x%x (unlocked=%d critical=%d)\n",
          (UINTN)(Di - Block), (UINTN)Di[DI_OFF_UNLOCKED], (UINTN)Di[DI_OFF_UNLOCK_CRITICAL]));
  Di[DI_OFF_UNLOCKED]        = 1;  /* is_unlocked */
  Di[DI_OFF_UNLOCK_CRITICAL] = 1;  /* is_unlock_critical */

  // 4. WRITE back (whole block, same size as READ).
  Status = SendDeviceStateCmd (Qseecom, AppId, KM_CMD_WRITE_DEVICE_STATE, Block, BlockSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: write cmd 515 failed: %r\n", Status));
    gBS->FreePages (BlockAddr, PageCount);
    return Status;
  }

  // 5. Verify (advisory): re-read and confirm flags. A failed re-read does not
  //    undo a successful write, so it only downgrades the result when the
  //    flags were actually read back as not-set.
  ZeroMem (Block, BlockSize);
  Status = SendDeviceStateCmd (Qseecom, AppId, KM_CMD_READ_DEVICE_STATE, Block, BlockSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_WARN, "KmDeviceStateApp: verify re-read failed (write already succeeded): %r\n", Status));
    Status = EFI_SUCCESS;
  } else {
    Di = FindDeviceInfo (Block, BlockSize);
    if (Di != NULL) {
      DEBUG ((EFI_D_INFO, "KmDeviceStateApp: verify unlocked=%d critical=%d\n",
              (UINTN)Di[DI_OFF_UNLOCKED], (UINTN)Di[DI_OFF_UNLOCK_CRITICAL]));
      if (Di[DI_OFF_UNLOCKED] != 1 || Di[DI_OFF_UNLOCK_CRITICAL] != 1) {
        DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: VERIFY FAILED (flags not persisted)\n"));
        Status = EFI_DEVICE_ERROR;
      }
    }
  }

  gBS->FreePages (BlockAddr, PageCount);
  return Status;
}

// ---------------------------------------------------------------------------
// Path 2 (fallback): mimic stock ABL / VbRwStateApp -
//                    QCOM_VERIFIEDBOOT_PROTOCOL.RWDeviceState
// ---------------------------------------------------------------------------
static EFI_STATUS
UnlockViaVerifiedBootProtocol (
  VOID
  )
{
  EFI_STATUS                  Status;
  QCOM_VERIFIEDBOOT_PROTOCOL *Vb     = NULL;
  UINT8                      *Buf    = NULL;
  UINT8                      *Di     = NULL;
  UINT32                      BufLen = VB_BUF_SIZE;

  Status = gBS->LocateProtocol (&mQcomVerifiedBootProtocolGuid, NULL, (VOID **)&Vb);
  if (EFI_ERROR (Status) || Vb == NULL || Vb->VBRwDeviceState == NULL) {
    DEBUG ((EFI_D_WARN, "KmDeviceStateApp: LocateProtocol(VerifiedBoot) failed: %r\n", Status));
    return Status;
  }

  Buf = AllocatePool (VB_BUF_SIZE);
  if (Buf == NULL) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: VB path alloc failed\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = Vb->VBRwDeviceState (Vb, READ_CONFIG, Buf, BufLen);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: VB READ_CONFIG failed: %r\n", Status));
    goto Exit;
  }

  Di = FindDeviceInfo (Buf, BufLen);
  if (Di == NULL) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: VB path: magic not found\n"));
    Status = EFI_NOT_FOUND;
    goto Exit;
  }
  DEBUG ((EFI_D_INFO, "KmDeviceStateApp: VB path: DeviceInfo @ +0x%x (unlocked=%d critical=%d)\n",
          (UINTN)(Di - Buf), (UINTN)Di[DI_OFF_UNLOCKED], (UINTN)Di[DI_OFF_UNLOCK_CRITICAL]));
  Di[DI_OFF_UNLOCKED]        = 1;
  Di[DI_OFF_UNLOCK_CRITICAL] = 1;

  Status = Vb->VBRwDeviceState (Vb, WRITE_CONFIG, Buf, BufLen);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: VB WRITE_CONFIG failed: %r\n", Status));
  } else {
    DEBUG ((EFI_D_INFO, "KmDeviceStateApp: VB WRITE_CONFIG success\n"));
  }

Exit:
  if (Buf != NULL) {
    FreePool (Buf);
  }
  return Status;
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------
EFI_STATUS
EFIAPI
KmDeviceStateAppEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;

  DEBUG ((EFI_D_INFO, "KmDeviceStateApp: start (DXE auto-run)\n"));

  // Prefer the direct-TA path (only depends on Qseecom protocol).
  Status = UnlockViaQseecom ();
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_WARN, "KmDeviceStateApp: direct TA path failed (%r), trying VB protocol\n", Status));
    Status = UnlockViaVerifiedBootProtocol ();
  }

  if (!EFI_ERROR (Status)) {
    DEBUG ((EFI_D_INFO, "KmDeviceStateApp: unlocked successfully (RPMB persisted)\n"));
  } else {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: unlock FAILED: %r\n", Status));
  }
  return Status;
}
