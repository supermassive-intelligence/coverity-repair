


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
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/si.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/si.c
@@ -1321,6 +1321,8 @@ static bool si_read_bios_from_rom(struct amdgpu_device *adev,
        length_dw = ALIGN(length_bytes, 4) / 4;
        /* set rom index to 0 */
        WREG32(mmROM_INDEX, 0);
+       if (length_dw * 4 > adev->bios_size)
+               return false;
        for (i = 0; i < length_dw; i++)
                dw_ptr[i] = RREG32(mmROM_DATA);

        return true;
========================================






========================================
Issue: Potential Buffer Overflow

CID: 1002
Severity: High
Type: Security
Category: Buffer Overflow
File: drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
Function: amdgpu_atombios_copy_swap
Line: 1630

Description:
A potential buffer overflow vulnerability exists because the code performs a memcpy operation without verifying if the num_bytes parameter exceeds the allocated size of the src_tmp buffer. When num_bytes is larger than src_tmp's capacity, the memcpy will write beyond the buffer's bounds.


========================================
============= reference diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
index 0c8975ac5af9..300e5d19a9e6 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
@@ -1625,6 +1625,9 @@ void amdgpu_atombios_copy_swap(u8 *dst, u8 *src, u8 num_bytes, bool to_le)
        u32 src_tmp[5], dst_tmp[5];
        int i;
        u8 align_num_bytes = ALIGN(num_bytes, 4);
+       if (align_num_bytes > sizeof(src_tmp)) {
+        return;
+    }

        if (to_le) {
                memcpy(src_tmp, src, num_bytes);

========================================
============= generated diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
index 622634c..3a2a16f 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
@@ -1627,6 +1627,9 @@ static int amdgpu_atombios_copy_swap(struct amdgpu_device *adev,
        int i;
        u8 align_num_bytes = ALIGN(num_bytes, 4);

+       if (num_bytes > sizeof(src_tmp)) {
+               return -EINVAL;
+       }
        if (to_le) {
                memcpy(src_tmp, src, num_bytes);
                for (i = 0; i < align_num_bytes / 4; i++)
========================================






========================================
Type: BUFFER_OVERFLOW
File: drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
Function: amdgpu_atif_verify_interface
Line: 255

Description: Potential buffer overflow in memcpy() operation
In amdgpu_atif_verify_interface, the size of the data to copy is read from info->buffer.pointer and directly used in a memcpy. If size of input->buffer.pointer exceeds the destination buffer (output), it can cause a buffer overflow. Before memcpy, add a check to ensure that output buffer is less than input->buffer.pointer.
========================================
============= reference diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
index f85ace0..fdfdd21 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
@@ -246,7 +246,7 @@ static int amdgpu_atif_verify_interface(struct amdgpu_atif *atif)
        memset(&output, 0, sizeof(output));

        size = *(u16 *) info->buffer.pointer;
-       if (size < 12) {
+       if (size < 12 || sizeof(output) < sizeof(info->buffer.pointer)) {
                DRM_INFO("ATIF buffer is too small: %zu\n", size);
                err = -EINVAL;
                goto out;
========================================
============= generated diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
@@ -252,6 +252,8 @@ static int amdgpu_atif_verify_interface(struct amdgpu_atif *atif)

        size = min(sizeof(output), size);

+       if (size > sizeof(output)) {
+               return -EINVAL;
+       }
        memcpy(&output, info->buffer.pointer, size);

        /* TODO: check version? */
========================================






========================================
Issue: Null Pointer Dereference
File: drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
Function: amdgpu_cs_parser_init
Line: 51

Description:
The function 'amdgpu_cs_parser_init' dereferences 'cs' without first checking if it is NULL. This can lead to a null pointer dereference if 'cs' is NULL when the function is called.
Code Path:

Function 'amdgpu_cs_parser_init' is called with 'cs' as an argument
'cs' is dereferenced at line 51 without a NULL check: if (cs->in.num_chunks == 0)


========================================
============= reference diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 1e475eb01417..d3db17084e3d 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -46,6 +46,8 @@ static int amdgpu_cs_parser_init(struct amdgpu_cs_parser *p,
                                 struct drm_file *filp,
                                 union drm_amdgpu_cs *cs)
 {
+       if (cs == NULL)
+               return -EINVAL;
        struct amdgpu_fpriv *fpriv = filp->driver_priv;

        if (cs->in.num_chunks == 0)

========================================
============= generated diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -48,6 +48,8 @@ static int amdgpu_cs_parser_init(struct amdgpu_cs_parser *p,
                return -EINVAL;

        memset(p, 0, sizeof(*p));
+       if (!cs) {
+               return -EINVAL;
        p->adev = adev;
        p->filp = filp;

@@ -57,7 +59,7 @@ static int amdgpu_cs_parser_init(struct amdgpu_cs_parser *p,

        p->ctx = amdgpu_ctx_get(fpriv, cs->in.ctx_id);
        if (!p->ctx) {
-               return -EINVAL;
+               return -ENOMEM;
        }

        return 0;
========================================






========================================
Issue: Potential Buffer Overflow in sprintf

CID: 1001
Type: Buffer Overflow
Severity: High
File: drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
Line: 150

Description:
The function sprintf is used to write to the buffer stmp without any length checking. This could lead to a buffer overflow if the formatted string exceeds the size of stmp.


========================================
============= reference diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
index 0c8975ac5af9..e215b5e2d183 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
@@ -147,7 +147,7 @@ void amdgpu_atombios_i2c_init(struct amdgpu_device *adev)
                        i2c = amdgpu_atombios_get_bus_rec_for_i2c_gpio(gpio);

                        if (i2c.valid) {
-                               sprintf(stmp, "0x%x", i2c.i2c_id);
+                               snprintf(stmp, sizeof(stmp), "0x%x", i2c.i2c_id);
                                adev->i2c_bus[i] = amdgpu_i2c_create(adev_to_drm(adev), &i2c, stmp);
                        }
                        gpio = (ATOM_GPIO_I2C_ASSIGMENT *)

========================================
============= generated diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
index bfd067e2d2f1..6419ab97d922 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
@@ -147,7 +147,7 @@ void amdgpu_atombios_i2c_init(struct amdgpu_device *adev)
                        i2c = amdgpu_atombios_get_bus_rec_for_i2c_gpio(gpio);

                        if (i2c.valid) {
-                               sprintf(stmp, "0x%x", i2c.i2c_id);
+                               snprintf(stmp, sizeof(stmp) "0x%x", i2c.i2c_id);
                                adev->i2c_bus[i] = amdgpu_i2c_create(adev_to_drm(adev), &i2c, stmp);
                        }
                        gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
========================================






========================================
File: drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c

Line: 2469

Function: amdgpu_amdkfd_gpuvm_import_dmabuf_fd

Description: 
*mem is dereferenced without a null check in (*mem)->gem_handle = handle. Add a null check.

========================================
============= reference diff =============
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c
@@ -2461,7 +2461,9 @@ int amdgpu_amdkfd_gpuvm_import_dmabuf_fd(struct amdgpu_device *adev, int fd,
        if (ret)
                goto err_put_obj;

-       (*mem)->gem_handle = handle;
+    if (*mem) {
+           (*mem)->gem_handle = handle;
+    }

        return 0;

========================================
============= generated diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c
@@ -2466,6 +2466,9 @@ static int amdgpu_amdkfd_gpuvm_import_dmabuf_fd(struct amdgpu_device *adev,
                return ret;

        (*mem)->gem_handle = handle;

+       if (*mem == NULL) {
+               return ret;
+       }
        return 0;
 }
========================================






========================================
Issue: Resource Leak
File: drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
Function: amdgpu_cs_pass1
Line: 218

Description:
A memory resource allocated using kvmalloc_array() may not be freed if an error occurs during execution.
The function amdgpu_cs_pass1 allocates memory for chunk_array using kvmalloc_array(). 
However, if an error occurs after this allocation but before the function successfully completes, the allocated memory may not be freed, resulting in a resource leak.


========================================
============= reference diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu_cs.c
index af43fd5..6dfdff5 100644
--- a/drivers/gpu/drm/amd/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu_cs.c
@@ -215,6 +215,7 @@ static int amdgpu_cs_pass1(struct amdgpu_cs_parser *p,
                if (copy_from_user(&user_chunk, chunk_ptr,
                                       sizeof(struct drm_amdgpu_cs_chunk))) {
                        ret = -EFAULT;
+                       i--;
                        goto free_partial_kdata;
                }
                p->chunks[i].chunk_id = user_chunk.chunk_id;

========================================
============= generated diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -215,6 +215,7 @@ static int amdgpu_cs_pass1(struct amdgpu_cs_parser *p,
                size = p->chunks[i].length_dw;
                cdata = u64_to_user_ptr(user_chunk.chunk_data);

+               if (!cdata)
+                       return -EFAULT;
                if (copy_from_user(&user_chunk, chunk_ptr,
                                   sizeof(struct drm_amdgpu_cs_chunk))) {
                        ret = -EFAULT;
========================================






========================================
Issue: Potential Memory Leak
File: drivers/gpu/drm/amd/amdgpu/amdgpu_atpx_handler.c
Line: 148

Description:
The function amdgpu_atpx_call allocates memory for buffer.pointer using ACPI_ALLOCATE_BUFFER, 
but does not free this memory in all code paths. Specifically, when the function succeeds 
(i.e., when acpi_evaluate_object does not fail), the allocated memory is returned to the caller without being freed.


========================================
============= reference diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_atpx_handler.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_atpx_handler.c
index 375f020..c5c86d9 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_atpx_handler.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_atpx_handler.c
@@ -144,7 +144,10 @@ static union acpi_object *amdgpu_atpx_call(acpi_handle handle, int function,
                kfree(buffer.pointer);
                return NULL;
        }
-
+       if (!buffer.pointer) {
+           pr_warn("ATPX buffer is NULL\n");
+           return NULL;
+       }
        return buffer.pointer;
}

========================================
============= generated diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_atpx_handler.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_atpx_handler.c
@@ -145,6 +145,10 @@ static char *amdgpu_atpx_call(struct amdgpu_atpx *atpx,
                return NULL;

        acpi_evaluate_object(hdev->acpi_dev, name, NULL, NULL);
+       if (!buffer.pointer) {
+               pr_warn("ACPI buffer is NULL");
+               return NULL;
+       }
        if (copy_from_user(buffer, size)) {
                pr_warn("copy_from_user failed");
                kfree(buffer.pointer);
========================================






========================================
Issue: Potential Buffer Overflow in Wave Assignment Logging
Type: Buffer Overflow
File: drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
Line: 427

Description:
A potential buffer overflow has been detected in the function gfx_v9_4_2_log_wave_assignment(). 
The function uses a fixed-size buffer of 256 bytes to store a formatted string, but does not implement proper bounds checking. 
This could lead to a buffer overflow if the accumulated string length exceeds the allocated buffer size.

========================================
============= reference diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c b/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
index 3f4fd2f..1f612a0 100644
--- a/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
+++ b/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
@@ -424,7 +424,9 @@ static void gfx_v9_4_2_log_wave_assignment(struct amdgpu_device *adev, uint32_t
        char *str;
        int size;

-       str = kmalloc(256, GFP_KERNEL);
+       int max_size = CU_ID_MAX * SIMD_ID_MAX * WAVE_ID_MAX * 64;
+
+       str = kmalloc(max_size, GFP_KERNEL);
        if (!str)
                return;

@@ -432,7 +434,7 @@ static void gfx_v9_4_2_log_wave_assignment(struct amdgpu_device *adev, uint32_t

        for (se = 0; se < adev->gfx.config.max_shader_engines; se++) {
                for (cu = 0; cu < CU_ID_MAX; cu++) {
-                       memset(str, 0, 256);
+                       memset(str, 0, max_size);
                        size = sprintf(str, "SE[%02d]CU[%02d]: ", se, cu);
                        for (simd = 0; simd < SIMD_ID_MAX; simd++) {
                                size += sprintf(str + size, "[");

========================================
============= generated diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
@@ -424,7 +424,8 @@ static int gfx_v9_4_2_log_wave_assignment(struct amdgpu_device *adev,
        char *str;
        int size;

-       str = kmalloc(256, GFP_KERNEL);
+       int max_buff_size = 256;
+       str = kmalloc(max_buff_size, GFP_KERNEL);
        if (!str)
                return;

@@ -432,7 +433,7 @@ static int gfx_v9_4_2_log_wave_assignment(struct amdgpu_device *adev,

                dev_dbg(adev->dev, "wave assignment:\n");

-               for (se = 0; se < adev->gfx.config.max_shader_engines; se++) {
+               if (max_buff_size - sprintf(str, "SE[%02d]CU[%02d]: ", se, cu) < 6) {
                        return;
                }
                for (cu = 
========================================






========================================
Type: Null pointer dereferences
File: drivers/gpu/drm/amd/amdgpu/amdgpu_gem.c
Function: amdgpu_gem_fault
Line: 50

Description:
The amdgpu_gem_fault function dereferences the pointer parameter vmf and its members (vmf->vma and vmf->vma->vm_private_data) without first verifying they are non-null. This can result in undefined behavior if any of these pointers are null. Add explicit null checks for vmf, vmf->vma, and vmf->vma->vm_private_data before attempting to access or assign to the bo variable.
========================================
============= reference diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_gem.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_gem.c
index 0e617df..722605f 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_gem.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_gem.c
@@ -47,6 +47,8 @@ static const struct drm_gem_object_funcs amdgpu_gem_object_funcs;

 static vm_fault_t amdgpu_gem_fault(struct vm_fault *vmf)
{
+       if (!vmf || !vmf->vma || !vmf->vma->vm_private_data)
+           return VM_FAULT_SIGSEGV;
        struct ttm_buffer_object *bo = vmf->vma->vm_private_data;
        struct drm_device *ddev = bo->base.dev;
        vm_fault_t ret;
========================================
============= generated diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_gem.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_gem.c
@@ -47,6 +47,10 @@ static const struct drm_gem_object_funcs amdgpu_gem_object_funcs;

 static vm_fault_t amdgpu_gem_fault(struct vm_fault *vmf)
 {
+       if (!vmf) {
+           return VM_FAULT_SIGSEGV;
+       }
        struct ttm_buffer_object *bo = vmf->vma->vm_private_data;
        struct drm_device *ddev = bo->base.dev;
        vm_fault_t ret;
========================================






========================================
CID: 12345
Classification: NULL_RETURNS
Function: aldebaran_get_reset_handler
File: drivers/gpu/drm/amd/amdgpu/aldebaran.c
Line: 50

Description:
The function 'aldebaran_get_reset_handler' dereferences 'reset_ctl->handle' without first checking if 
'reset_ctl' or 'reset_ctl->handle' is NULL. This could lead to a null pointer dereference if either 
'reset_ctl' or 'reset_ctl->handle' is NULL when the function is called.


========================================
============= reference diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c
index b0f95a7..3c12e3b 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c
@@ -47,6 +47,9 @@ aldebaran_get_reset_handler(struct amdgpu_reset_control *reset_ctl,
                            struct amdgpu_reset_context *reset_context)
 {
        struct amdgpu_reset_handler *handler;
+       if (!reset_ctl || !reset_ctl->handle) {
+               return NULL;
+       }
        struct amdgpu_device *adev = (struct amdgpu_device *)reset_ctl->handle;
        int i;

========================================
============= generated diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c
index 622634c..3a2a16f 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c
@@ -47,6 +47,9 @@ aldebaran_get_reset_handler(struct amdgpu_reset_control *reset_ctl,
                             struct amdgpu_reset_context *reset_context)
 {
        struct amdgpu_reset_handler *handler;
+       if (!reset->ctl || !reset_ctl->handle) {
+               return NULL;
+       }
        struct amdgpu_device *adev = (struct amdgpu_device *)reset_ctl->handle;
        int i;

@@ -57,7 +60,6 @@ aldebaran_get_reset_handler(struct amdgpu_reset_control *reset_ctl,
                struct amdgpu_reset_context *reset_context)

========================================






========================================
Integer Overflow in cik_read_bios_from_rom
CID: 2002

Severity: High
Type: Integer Overflow
File: drivers/gpu/drm/amd/amdgpu/cik.c
Line: 1028
Location: cik_read_bios_from_rom function
Description
A potential integer overflow has been detected in the cik_read_bios_from_rom function. 
The variable dw_ptr, which is of type u8, is assigned the result of an ALIGN 
macro operation that can produce values greater than 255 for certain inputs of length_bytes.

u8 dw_ptr = ALIGN(length_bytes, 4);


========================================
============= reference diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/cik.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/cik.c
index d8e1a6d..782554f 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/cik.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/cik.c
@@ -1025,7 +1025,7 @@ static bool cik_read_bios_from_rom(struct amdgpu_device *adev,
                return false;

        dw_ptr = (u32 *)bios;
-       u8 length_dw = ALIGN(length_bytes, 4);
+       u32 length_dw = ALIGN(length_bytes, 4);
        /* take the smc lock since we are using the smc index */
        spin_lock_irqsave(&adev->smc_idx_lock, flags);
        /* set rom index to 0 */
========================================
============= generated diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/cik.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/cik.c
index 622634c..3a2a16f 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/cik.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/cik.c
@@ -1025,7 +1025,7 @@ static bool cik_read_bios_from_rom(struct amdgpu_device *adev,
                return false;

        dw_ptr = (u32 *)bios;
-       u8 length_dw = ALIGN(length_bytes, 4);
+       u32 length_dw = ALIGN(length_bytes, 4);
        /* take the smc lock since we are using the smc index */
        spin_lock_irqsave(&adev->smc_idx_lock, flags);
        /* set rom index to 0 */
========================================



