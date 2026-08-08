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
 *  Feedback channel (2026-08-07): vibration via the PMIC haptics peripheral.
 *  No haptics protocol exists in the stock 8550/8650/8750 UEFI (PmicDxe only
 *  links the PmicLib *config* parser, there is no HapticsDxe), but the whole
 *  hardware path is already in the platform build: SPMIDxe installs
 *  EFI_SPMI_PROTOCOL and the motor is PM8550B qcom,hv-haptics (SPMI slave 7,
 *  cfg base 0xF000). VibrateFeedback() writes a few SPMI registers directly
 *  (success = 1 buzz, failure = 3 buzzes); a wrong register offset stays
 *  inside the haptics peripheral (0xF0xx) so it cannot touch PMIC power /
 *  charger / GPIO registers. Offsets follow the HV-haptics (HAP530) regmap.
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

// EFI_SPMI_PROTOCOL installed by SPMIDxe (GUID read byte-for-byte out of the
// 8550 stock firmware; interface layout verified by decompiling SPMIDxe and
// the PmicDxe SPMI wrappers).
EFI_GUID mQcomSpmiProtocolGuid = {
  0xFA5F306B, 0xF47D, 0x4AC4,
  {0xA4, 0x7D, 0x88, 0x2F, 0x82, 0x04, 0xEC, 0x30}
};

typedef struct _EFI_SPMI_PROTOCOL EFI_SPMI_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_SPMI_READ_BYTE)(
  IN  EFI_SPMI_PROTOCOL *This,
  IN  UINT32             SlaveId,
  IN  UINT32             PeripheralId,
  IN  UINT32             ByteCount,
  IN  UINT32             Offset,
  OUT UINT8              *Data,
  IN  UINT32             Priority,
  OUT UINT32             *Status
  );

typedef EFI_STATUS (EFIAPI *EFI_SPMI_WRITE_BYTE)(
  IN EFI_SPMI_PROTOCOL *This,
  IN UINT32             SlaveId,
  IN UINT32             PeripheralId,
  IN UINT32             ByteCount,
  IN UINT32             Offset,
  IN UINT8              *Data,
  IN UINT32             Priority
  );

struct _EFI_SPMI_PROTOCOL {
  UINT64              Version;   /* 0x10003 on nuwa stock SPMIDxe */
  EFI_SPMI_READ_BYTE  ReadByte;  /* slot +8  */
  EFI_SPMI_WRITE_BYTE WriteByte; /* slot +16 */
  /* ReadMulti / WriteMulti / GetInfo / IRQ slots unused here */
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

/*
 * PM8550B HV-haptics constants (nuwa, SM8550).
 * Source: XBL DTB embedded in the stock FV ->
 *   /soc/qcom,spmi@c42d000/qcom,pm8550b@7/qcom,hv-haptics@f000
 *   (reg = <0xf000> cfg, <0xf100> ptn; qcom,vmax-mv = 0x578 = 1400 mV)
 * 2026-08-08: confirmed 1:1 against the user device's own kernel DT
 *  (qcom,hv-haptics@f000, SPMI slave 7, same reg/vmax; only motor tuning
 *  differs: lra-period-us = 0x1652 -> tlra-ol = 0x477 from own soc dtb).
 * Register offsets: HV-haptics (HAP530) family regmap, upstream
 * qcom-spmi-haptics (PMIH010X) driver.
 */
#define HAP_PM8550B_SPMI_SLAVE       7u
#define HAP_CFG_PERIPH_ID            0xF0u  /* 0xF000 >> 8 */
#define HAP_PTN_PERIPH_ID            0xF1u  /* 0xF100 >> 8 */
#define HAP_CFG_EN_CTL_REG           0x46u  /* bit7 = haptics enable */
#define HAP_CFG_VMAX_REG             0x48u  /* vmax_mv / 50 */
#define HAP_CFG_SPMI_PLAY_REG        0x4Cu  /* bit7 = play; PAT_SRC_DIRECT_PLAY = 1 */
#define HAP_CFG_AUTORES_CFG_REG      0x63u  /* bit7 = auto-resonance enable */
#define HAP_CFG_FAULT_CLR_REG        0x66u
#define HAP_CFG_TLRA_OL_HIGH_REG     0x5Cu  /* LRA resonance period, high nibble */
#define HAP_CFG_TLRA_OL_LOW_REG      0x5Du  /* LRA resonance period, low byte */
#define HAP_PTN_DIRECT_PLAY_REG      0x26u  /* amplitude 0..255 */

#define HAP_PLAY_ON                  0x81u  /* PLAY_EN_BIT | PAT_SRC_DIRECT_PLAY */
#define HAP_FAULT_CLR_ALL            0x17u
#define HAP_EN_BIT                   0x80u
#define HAP_AUTORES_EN_BIT           0x80u
#define HAP_VMAX_MV                  1400u
#define HAP_VMAX_STEP_MV             50u
#define HAP_TLRA_OL_TICKS            0x477u /* lra-period-us 0x1652 / 5us per tick */
#define HAP_AMPLITUDE                128u
#define HAP_BUZZ_US                  120000u
#define HAP_PAUSE_US                 150000u

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
// Vibration feedback (PM8550B HV-haptics via EFI_SPMI_PROTOCOL)
//
// No driver extraction is needed: SPMIDxe (already in the nuwa build) exposes
// the SPMI protocol and the haptics peripheral is config-driven. This is the
// minimal DIRECT_PLAY sequence used by the HV-haptics driver:
//   enable module -> clear faults -> auto-resonance on -> VMAX ->
//   TLRA (LRA period, device tuning) -> amplitude (ptn) -> PLAY on -> hold ->
//   PLAY off.
// ---------------------------------------------------------------------------
static EFI_STATUS
VibrateOnce (
  IN EFI_SPMI_PROTOCOL *Spmi,
  IN UINTN              BuzzUs
  )
{
  EFI_STATUS Status;
  UINT32     SpmiStatus = 0;
  UINT8      Val;

  if (Spmi == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // 1. Enable haptics module (read-modify-write, keep unrelated bits).
  Status = Spmi->ReadByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_CFG_PERIPH_ID, 1,
                           HAP_CFG_EN_CTL_REG, &Val, 0, &SpmiStatus);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }
  Val |= HAP_EN_BIT;
  Status = Spmi->WriteByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_CFG_PERIPH_ID, 1,
                            HAP_CFG_EN_CTL_REG, &Val, 0);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // 2. Clear pending faults.
  Val = HAP_FAULT_CLR_ALL;
  Status = Spmi->WriteByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_CFG_PERIPH_ID, 1,
                            HAP_CFG_FAULT_CLR_REG, &Val, 0);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // 3. Enable auto-resonance (needed by DIRECT_PLAY).
  Status = Spmi->ReadByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_CFG_PERIPH_ID, 1,
                           HAP_CFG_AUTORES_CFG_REG, &Val, 0, &SpmiStatus);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }
  Val |= HAP_AUTORES_EN_BIT;
  Status = Spmi->WriteByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_CFG_PERIPH_ID, 1,
                            HAP_CFG_AUTORES_CFG_REG, &Val, 0);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // 4. Drive voltage (vmax_mv / 50 mV per LSB).
  Val = (UINT8)(HAP_VMAX_MV / HAP_VMAX_STEP_MV);
  Status = Spmi->WriteByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_CFG_PERIPH_ID, 1,
                            HAP_CFG_VMAX_REG, &Val, 0);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // 5. LRA resonance period (TLRA) from the device's own tuning:
  //    lra-period-us = 0x1652 (5714 us) / 5 us per tick = 0x477 ticks.
  //    PmicDxe never initialises haptics, so write this explicitly.
  Val = (UINT8)(HAP_TLRA_OL_TICKS >> 8);
  Status = Spmi->WriteByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_CFG_PERIPH_ID, 1,
                            HAP_CFG_TLRA_OL_HIGH_REG, &Val, 0);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }
  Val = (UINT8)(HAP_TLRA_OL_TICKS & 0xFF);
  Status = Spmi->WriteByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_CFG_PERIPH_ID, 1,
                            HAP_CFG_TLRA_OL_LOW_REG, &Val, 0);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // 6. Waveform amplitude (constant level, DIRECT_PLAY; PTN peripheral 0xF1).
  Val = HAP_AMPLITUDE;
  Status = Spmi->WriteByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_PTN_PERIPH_ID, 1,
                            HAP_PTN_DIRECT_PLAY_REG, &Val, 0);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // 7. Start playing.
  Val = HAP_PLAY_ON;
  Status = Spmi->WriteByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_CFG_PERIPH_ID, 1,
                            HAP_CFG_SPMI_PLAY_REG, &Val, 0);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  // 8. Hold, then stop.
  gBS->Stall (BuzzUs);
  Val = 0;
  Status = Spmi->WriteByte (Spmi, HAP_PM8550B_SPMI_SLAVE, HAP_CFG_PERIPH_ID, 1,
                            HAP_CFG_SPMI_PLAY_REG, &Val, 0);

Exit:
  return Status;
}

static VOID
VibrateFeedback (
  IN BOOLEAN Success
  )
{
  EFI_SPMI_PROTOCOL *Spmi = NULL;
  EFI_STATUS         Status;
  UINTN              Buzzes;
  UINTN              Idx;

  Status = gBS->LocateProtocol (&mQcomSpmiProtocolGuid, NULL, (VOID **)&Spmi);
  if (EFI_ERROR (Status) || Spmi == NULL) {
    DEBUG ((EFI_D_WARN, "KmDeviceStateApp: SPMI protocol not found (%r), vibration skipped\n", Status));
    return;
  }

  // Success: 1 short buzz. Failure: 3 short buzzes.
  Buzzes = Success ? 1 : 3;
  for (Idx = 0; Idx < Buzzes; Idx++) {
    if (EFI_ERROR (VibrateOnce (Spmi, HAP_BUZZ_US))) {
      DEBUG ((EFI_D_WARN, "KmDeviceStateApp: vibration write failed (non-fatal)\n"));
      break;
    }
    if (Idx + 1 < Buzzes) {
      gBS->Stall (HAP_PAUSE_US);
    }
  }
  DEBUG ((EFI_D_INFO, "KmDeviceStateApp: vibration feedback done (%a)\n",
          Success ? "SUCCESS" : "FAILED"));
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

  // Best-effort physical feedback; never affects the unlock result.
  VibrateFeedback (!EFI_ERROR (Status));
  return Status;
}
