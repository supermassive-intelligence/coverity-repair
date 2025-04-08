


========================================
Issue: Lack of Boundary Checks
Type: BUFFER_OVERFLOW
File: drivers/gpu/drm/amd/amdgpu/si.c
Line: 1324

Description:
The function si_read_bios_from_rom lacks proper boundary checks when reading data into the bios buffer. 
The function calculates the number of dwords to read based on the input length_bytes, but it doesn't verify 
if this calculated length exceeds the actual allocated size of the bios buffer. 
This can lead to a buffer overflow, potentially causing memory corruption or security vulnerabilities.


========================================
============= reference diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu/si.c b/drivers/gpu/drm/amd/amdgpu/si.c
index 8523547..c64b7ac 100644
--- a/drivers/gpu/drm/amd/amdgpu/si.c
+++ b/drivers/gpu/drm/amd/amdgpu/si.c
@@ -1319,6 +1319,8 @@ static bool si_read_bios_from_rom(struct amdgpu_device *adev,

        dw_ptr = (u32 *)bios;
        length_dw = ALIGN(length_bytes, 4) / 4;
+       if (length_dw * 4 > adev->bios_size)
+               return false;
        /* set rom index to 0 */
        WREG32(mmROM_INDEX, 0);
        for (i = 0; i < length_dw; i++)

========================================
============= generated diff =============


diff --git a/drivers/gpu/drm/amd/amdgpu/si.c b/drivers/gpu/drm/amd/amdgpu/si.c
index 1234567..c64b7ac 100644
--- a/drivers/gpu/drm/amd/amdgpu/si.c
+++ b/drivers/gpu/drm/amd/amdgpu/si.c
@@ -1319,6 +1319,8 @@ static bool si_read_bios_from_rom(struct amdgpu_device *adev,

     dw_ptr = (u32 *)bios;
     length_dw = ALIGN(length_bytes, 4) / 4;
+    if (length_dw * 4 > adev->bios_size)
+        return false;
     /* set rom index to 0 */
     WREG32(mmROM_INDEX, 0);
     for (i = 0; i < length_dw; i++)
         dw_ptr[i] = RREG32(mmROM_DATA);
========================================



