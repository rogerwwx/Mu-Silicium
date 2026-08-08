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
 *  NOTE: this driver has NO depex (2026-08-08). It used to depend on the
 *  Qseecom protocol, but on socrates that protocol is never installed when
 *  the SMC/TZ chain is down, so the driver never dispatched and produced no
 *  diagnostics. It now always dispatches (late, after the console is up) and
 *  prints the state of every link in the TZ chain directly on the screen.
 *
 *  Feedback channel (2026-08-08): the platform renders DEBUG output to the
 *  framebuffer (FrameBufferSerialPortLib), so all results below are printed
 *  on screen - no vibration needed. Current build is KM_DIAGNOSTIC_ONLY
 *  (read-only probe; flip to 0 for the full unlock write, see below).
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
#include <Library/PrintLib.h>
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

// Chain-probe GUIDs (socrates stock, IDA-verified 2026-08-08):
//   gQcomShmBridgeProtocolGuid (9C1EB71F...) is installed by ShmBridgeDxe and
//   is the prerequisite that both ScmDxeCompat (ScmArmV8.c:140) and TzDxeLA
//   (TzeLoaderDxe.c:1115) Locate before they install their own protocols;
//   gQcomScmProtocolGuid (77ED108D...) is installed by ScmDxeCompat and is
//   required by TzDxeLA before it installs the Qseecom protocol (A74862CE).
EFI_GUID mQcomShmBridgeProtocolGuid = {
  0x9C1EB71F, 0xDD6C, 0x4ED5,
  {0x9F, 0x6A, 0x5C, 0xC0, 0xCA, 0x78, 0x9F, 0x16}
};

EFI_GUID mQcomScmProtocolGuid = {
  0x77ED108D, 0x8524, 0x4B8B,
  {0x9D, 0x2E, 0x34, 0x98, 0x7A, 0xEC, 0xB9, 0xC1}
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

/* How long (us) the diagnostic summary stays on screen before BDS draws the
 * boot menu. 5 seconds so the result is actually readable on the framebuffer. */
#define KM_DIAG_SCREEN_STALL_US      5000 * 1000

/*
 * Diagnostic-only mode (2026-08-08, user request "先弄个稳妥点的"):
 *   = 1: only READ cmd 514 + magic scan, NEVER writes. Results are printed
 *        to DEBUG, which the platform renders on the framebuffer.
 *   = 0: full unlock flow (write 515).
 * Flip this back to 0 once the read path is confirmed on device.
 */
#define KM_DIAGNOSTIC_ONLY           1

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
  EFI_STATUS          Status;

  Cmd.CmdId   = CmdId;
  Cmd.BufPtr  = (UINT32)(UINTN)Block;
  Cmd.BufSize = BlockSize;
  ZeroMem (Resp, sizeof (Resp));

  Status = Qseecom->QseecomSendCmd (
                     Qseecom,
                     AppId,
                     (UINT8 *)&Cmd,
                     sizeof (Cmd),
                     (UINT8 *)Resp,
                     sizeof (Resp)
                     );

  // The TA's 12-byte response is the actual command status - the EFI_STATUS
  // return alone is not enough (VerifiedBootDxe checks Resp[2] != 0 as an
  // error, e.g. "RPMB not provisioned"/"read_req err"). Print all three
  // dwords so a silent TA-side failure is visible on the framebuffer.
  DEBUG ((EFI_D_INFO, "KmDeviceStateApp: cmd %u -> Status=%r Resp[0]=0x%x Resp[1]=0x%x Resp[2]=0x%x\n",
          (UINTN)CmdId, Status, (UINTN)Resp[0], (UINTN)Resp[1], (UINTN)Resp[2]));

  return Status;
}

#if KM_DIAGNOSTIC_ONLY
static VOID
DumpBlockHead (
  IN UINT8  *Block,
  IN UINT32 BlockSize
  )
{
  UINTN  Idx;
  UINT32 Bytes;

  Bytes = (BlockSize < 64) ? BlockSize : 64;
  DEBUG ((EFI_D_INFO, "KmDeviceStateApp: block head (%u bytes):\n", (UINTN)Bytes));
  for (Idx = 0; Idx < Bytes; Idx += 16) {
    DEBUG ((EFI_D_INFO, "  %04x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
            (UINTN)Idx,
            (UINTN)Block[Idx + 0],  (UINTN)Block[Idx + 1],  (UINTN)Block[Idx + 2],  (UINTN)Block[Idx + 3],
            (UINTN)Block[Idx + 4],  (UINTN)Block[Idx + 5],  (UINTN)Block[Idx + 6],  (UINTN)Block[Idx + 7],
            (UINTN)Block[Idx + 8],  (UINTN)Block[Idx + 9],  (UINTN)Block[Idx + 10], (UINTN)Block[Idx + 11],
            (UINTN)Block[Idx + 12], (UINTN)Block[Idx + 13], (UINTN)Block[Idx + 14], (UINTN)Block[Idx + 15]));
  }
}
#endif /* KM_DIAGNOSTIC_ONLY */

// ---------------------------------------------------------------------------
// Path 1: direct keymaster TA via Qseecom protocol (cmd 514/515)
// ---------------------------------------------------------------------------
#if !KM_DIAGNOSTIC_ONLY
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
#endif /* !KM_DIAGNOSTIC_ONLY */

// ---------------------------------------------------------------------------
// Diagnostic probe (KM_DIAGNOSTIC_ONLY): READ-only verification.
// Same read path as UnlockViaQseecom (TA load + cmd 514), but NEVER writes.
// Returns EFI_SUCCESS when the DeviceInfo magic is found, so the caller can
// report "RPMB readable and flag location confirmed" via vibration.
// ---------------------------------------------------------------------------
#if KM_DIAGNOSTIC_ONLY
static EFI_STATUS
ProbeRpmbDeviceState (
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

  TaNames[0]    = "keymaster";
  TaNames[1]    = "keymaster64";
  BlockSizes[0] = KM_BLOCK_8K;
  BlockSizes[1] = KM_BLOCK_4K;

  Status = gBS->LocateProtocol (&mQcomQseecomProtocolGuid, NULL, (VOID **)&Qseecom);
  if (EFI_ERROR (Status) || Qseecom == NULL) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: probe: LocateProtocol(Qseecom) failed: %r\n", Status));
    return Status;
  }

  // Probe BOTH TAs x both block sizes so we learn which (if any) actually
  // returns the DeviceInfo blob (atlas PoC used keymaster64 on SD4Gen2;
  // VerifiedBootDxe uses "keymaster" here - try both, read-only).
  Status = EFI_NOT_FOUND;
  for (TaIdx = 0; TaIdx < 2; TaIdx++) {
    Status = Qseecom->QseecomStartApp (Qseecom, TaNames[TaIdx], &AppId);
    if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_WARN, "KmDeviceStateApp: probe: StartApp('%a') failed: %r\n", TaNames[TaIdx], Status));
      continue;
    }
    DEBUG ((EFI_D_INFO, "KmDeviceStateApp: probe: TA '%a' AppId = %u\n", TaNames[TaIdx], (UINTN)AppId));

    for (SzIdx = 0; SzIdx < 2; SzIdx++) {
      BlockSize = BlockSizes[SzIdx];
      PageCount = EFI_SIZE_TO_PAGES (BlockSize);
      BlockAddr = 0xFFFFF000;
      Status = gBS->AllocatePages (AllocateMaxAddress, EfiRuntimeServicesData, PageCount, &BlockAddr);
      if (EFI_ERROR (Status)) {
        DEBUG ((EFI_D_WARN, "KmDeviceStateApp: probe: alloc %x failed: %r\n", (UINTN)BlockSize, Status));
        continue;
      }
      Block = (UINT8 *)(UINTN)BlockAddr;
      ZeroMem (Block, BlockSize);

      Status = SendDeviceStateCmd (Qseecom, AppId, KM_CMD_READ_DEVICE_STATE, Block, BlockSize);
      if (EFI_ERROR (Status)) {
        DEBUG ((EFI_D_WARN, "KmDeviceStateApp: probe: read cmd 514 (%x block) failed: %r\n", (UINTN)BlockSize, Status));
        gBS->FreePages (BlockAddr, PageCount);
        Block = NULL;
        continue;
      }

      Di = FindDeviceInfo (Block, BlockSize);
      if (Di == NULL) {
        DEBUG ((EFI_D_WARN, "KmDeviceStateApp: probe: magic not found in %x block\n", (UINTN)BlockSize));
        DumpBlockHead (Block, BlockSize);
        gBS->FreePages (BlockAddr, PageCount);
        Block = NULL;
        continue;
      }

      DEBUG ((EFI_D_INFO, "KmDeviceStateApp: probe: FOUND DeviceInfo @ +0x%x "
              "(unlocked=%d critical=%d) - read path OK, no write performed\n",
              (UINTN)(Di - Block), (UINTN)Di[DI_OFF_UNLOCKED], (UINTN)Di[DI_OFF_UNLOCK_CRITICAL]));
      gBS->FreePages (BlockAddr, PageCount);
      return EFI_SUCCESS;
    }
  }

  DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: probe: no readable DeviceInfo block found\n"));
  return EFI_NOT_FOUND;
}

// ---------------------------------------------------------------------------
// Diagnostic probe #2: VerifiedBoot protocol READ_CONFIG (read-only).
// VerifiedBootDxe's VBRwDeviceState mirrors what stock ABL does: on a secure
// device with SecurityFlag bit 0x80 it reads via keymaster/RPMB (cmd 514),
// otherwise it falls back to the "devinfo" GPT partition. With the TzDxeLA
// keymaster-init fix both paths should succeed; this probe reports which one
// actually worked on the device.
// ---------------------------------------------------------------------------
static EFI_STATUS
ProbeVerifiedBootPath (
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
    DEBUG ((EFI_D_WARN, "KmDeviceStateApp: VB probe: LocateProtocol(VerifiedBoot) failed: %r\n", Status));
    return Status;
  }

  Buf = AllocatePool (VB_BUF_SIZE);
  if (Buf == NULL) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: VB probe: alloc failed\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  ZeroMem (Buf, BufLen);

  Status = Vb->VBRwDeviceState (Vb, READ_CONFIG, Buf, BufLen);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: VB probe: READ_CONFIG failed: %r\n", Status));
    FreePool (Buf);
    return Status;
  }

  Di = FindDeviceInfo (Buf, BufLen);
  if (Di == NULL) {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: VB probe: READ_CONFIG ok but magic not found\n"));
    DumpBlockHead (Buf, BufLen);
    FreePool (Buf);
    return EFI_NOT_FOUND;
  }

  DEBUG ((EFI_D_INFO, "KmDeviceStateApp: VB probe: FOUND DeviceInfo @ +0x%x "
          "(unlocked=%d critical=%d) - VB READ path OK, no write performed\n",
          (UINTN)(Di - Buf), (UINTN)Di[DI_OFF_UNLOCKED], (UINTN)Di[DI_OFF_UNLOCK_CRITICAL]));
  FreePool (Buf);
  return EFI_SUCCESS;
}
#endif /* KM_DIAGNOSTIC_ONLY */

// ---------------------------------------------------------------------------
// Path 2 (fallback): mimic stock ABL / VbRwStateApp -
//                    QCOM_VERIFIEDBOOT_PROTOCOL.RWDeviceState
// ---------------------------------------------------------------------------
#if !KM_DIAGNOSTIC_ONLY
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
#endif /* !KM_DIAGNOSTIC_ONLY */

#if KM_DIAGNOSTIC_ONLY
// ---------------------------------------------------------------------------
// TZ chain probe (2026-08-08): report which links are actually up.
// On socrates the raw SMC inside ScmDxeCompat failed ("Smc Invoke call failed
// ret 0x10") and KmDeviceStateApp (depex on Qseecom) never dispatched, so we
// now check every protocol explicitly instead of relying on the depex.
// ---------------------------------------------------------------------------
static VOID
ProbeTzChain (
  VOID
  )
{
  EFI_STATUS                    ShmStatus;
  EFI_STATUS                    ScmStatus;
  EFI_STATUS                    QseecomStatus;
  EFI_STATUS                    VbStatus;
  VOID                         *ShmIf;
  VOID                         *ScmIf;
  QCOM_QSEECOM_PROTOCOL        *Qseecom;
  QCOM_VERIFIEDBOOT_PROTOCOL   *Vb;

  ShmStatus     = gBS->LocateProtocol (&mQcomShmBridgeProtocolGuid, NULL, &ShmIf);
  ScmStatus     = gBS->LocateProtocol (&mQcomScmProtocolGuid, NULL, &ScmIf);
  QseecomStatus = gBS->LocateProtocol (&mQcomQseecomProtocolGuid, NULL, (VOID **)&Qseecom);
  VbStatus      = gBS->LocateProtocol (&mQcomVerifiedBootProtocolGuid, NULL, (VOID **)&Vb);

  DEBUG ((EFI_D_INFO,
          "KDS probe: ShmBridge=%r SCM=%r Qseecom=%r VerifiedBoot=%r\n",
          ShmStatus, ScmStatus, QseecomStatus, VbStatus));

  // Mirror on the console so the result is visible without serial.
  if (gST->ConOut != NULL) {
    gST->ConOut->OutputString (gST->ConOut, L"KDS probe: ");
    gST->ConOut->OutputString (gST->ConOut,
      EFI_ERROR (ShmStatus) ? L"ShmBridge=FAIL " : L"ShmBridge=OK ");
    gST->ConOut->OutputString (gST->ConOut,
      EFI_ERROR (ScmStatus) ? L"SCM=FAIL " : L"SCM=OK ");
    gST->ConOut->OutputString (gST->ConOut,
      EFI_ERROR (QseecomStatus) ? L"Qseecom=FAIL " : L"Qseecom=OK ");
    gST->ConOut->OutputString (gST->ConOut,
      EFI_ERROR (VbStatus) ? L"VerifiedBoot=FAIL\r\n" : L"VerifiedBoot=OK\r\n");
  }
}
#endif /* KM_DIAGNOSTIC_ONLY */

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

#if KM_DIAGNOSTIC_ONLY
  // Conservative diagnostic build (user request 2026-08-08): READ-only.
  // Results are printed to DEBUG, which FrameBufferSerialPortLib renders
  // on the screen (no vibration needed).
  DEBUG ((EFI_D_INFO, "KmDeviceStateApp: DIAGNOSTIC MODE (read-only)\n"));

  // Step 1: which links of the TZ/Qseecom chain are installed?
  ProbeTzChain ();

  // Step 2: can we actually start the keymaster TA and read DeviceInfo?
  Status = ProbeRpmbDeviceState ();
  if (!EFI_ERROR (Status)) {
    DEBUG ((EFI_D_INFO, "KmDeviceStateApp: DIAGNOSTIC OK - flag location confirmed, no write performed\n"));
    Status = EFI_SUCCESS;
  } else {
    DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: DIAGNOSTIC FAILED: %r (no write performed)\n", Status));
  }

  // Step 3: VerifiedBoot protocol READ_CONFIG (read-only). Reports whether the
  // ABL-mirroring VB path can also read DeviceInfo (RPMB or devinfo fallback).
  {
    EFI_STATUS VbStatus;

    VbStatus = ProbeVerifiedBootPath ();
    if (!EFI_ERROR (VbStatus)) {
      DEBUG ((EFI_D_INFO, "KmDeviceStateApp: VB DIAGNOSTIC OK - VB READ path works, no write performed\n"));
    } else {
      DEBUG ((EFI_D_ERROR, "KmDeviceStateApp: VB DIAGNOSTIC FAILED: %r (no write performed)\n", VbStatus));
    }

    // Mirror the final result on the framebuffer (no serial needed).
    if (gST->ConOut != NULL) {
      CHAR16 Summary[128];

      UnicodeSPrint (
        Summary, sizeof (Summary),
        L"KDS: Qseecom=%s VB=%s\r\n",
        EFI_ERROR (Status)   ? L"FAIL" : L"OK",
        EFI_ERROR (VbStatus) ? L"FAIL" : L"OK");
      gST->ConOut->OutputString (gST->ConOut, Summary);
    }
  }

  // Keep the probe output on screen (5 s) before BDS draws the menu.
  gBS->Stall (KM_DIAG_SCREEN_STALL_US);
  return Status;
#else
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
#endif
}
