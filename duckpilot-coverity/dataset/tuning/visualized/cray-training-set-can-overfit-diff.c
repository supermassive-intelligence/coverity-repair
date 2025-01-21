


========================================
CID: 492835
Type: Buffer overflow
Severity: High
Checker: BUFFER_SIZE
Category: SECURE_CODING
File: drivers/gpu/drm/amd/amdgpu/amdgpu_fru_eeprom.c
Function: amdgpu_fru_get_product_info
Line: 131

Problem:
Potential buffer overflow when formatting device serial number using sprintf

Abstract:
The code uses sprintf to write a hexadecimal string representation of a 64-bit 
unique ID into the fru_info->serial buffer without size checking. This could 
lead to a buffer overflow if the destination buffer is smaller than the 
formatted string length (including null terminator).

Path:
  drivers/gpu/drm/amd/amdgpu/amdgpu_fru_eeprom.c:131
    sprintf(fru_info->serial, "%llx", adev->unique_id)

Details:
Converting a 64-bit value to hexadecimal format using sprintf can produce up to 
16 characters plus a null terminator. Without bounds checking, this operation 
risks writing beyond the end of the serial buffer if it's smaller than 17 bytes. 
The code handles critical device identification information in kernel space, 
making buffer overflows particularly dangerous.

Fix:
Replace sprintf with snprintf to enforce buffer size limits:
  snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id)

========================================
============= reference diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_fru_eeprom.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_fru_eeprom.c
index ceb5163480f4..a4696976c809 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_fru_eeprom.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_fru_eeprom.c
@@ -131,7 +131,7 @@ int amdgpu_fru_get_product_info(struct amdgpu_device *adev)
         * so convert it to a 16-digit HEX string for convenience and
         * backwards-compatibility.
         */
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

        /* If algo exists, it means that the i2c_adapter's initialized */
        if (!adev->pm.fru_eeprom_i2c_bus || !adev->pm.fru_eeprom_i2c_bus->algo) {
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_fru_eeprom.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_fru_eeprom.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_fru_eeprom.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_fru_eeprom.c
@@ -131,7 +131,7 @@ int amdgpu_fru_get_product_info(struct amdgpu_device *adev)
         * so convert it to a 16-digit HEX string for convenience and
         * backwards-compatibility.
         */
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If algo exists, it means that the i2c_adapter's initialized */
	*so convert it to a 16-digit HEX string for convenience and
	*backwards-compatibility.
	*/
-       sprintf(fru_info->serial, "%llx", adev->unique_id);
+       snprintf(fru_info->serial, sizeof(fru_info->serial), "%llx", adev->unique_id);

	/* If
========================================






========================================
File: drivers/gpu/drm/amd/amdgpu/amdgpu_preempt_mgr.c

Line: 69

Function: amdgpu_preempt_mgr_new(

Description: Use of freed memory:
 *res may have been freed inside of ttm_resource_init

Consider adding a check for NULL.

========================================
============= reference diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_preempt_mgr.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_preempt_mgr.c
@@ -66,7 +66,9 @@ static int amdgpu_preempt_mgr_new(struct ttm_resource_manager *man,
                return -ENOMEM;

        ttm_resource_init(tbo, place, *res);
-       (*res)->start = AMDGPU_BO_INVALID_OFFSET;
+       if (*res) {
+           (*res)->start = AMDGPU_BO_INVALID_OFFSET;
+       }
        return 0;
 }
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preempt_mgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c
@@ -69,7 +69,7 @@ int amdgpu_preemptmgr_new(struct amdgpu_device *tbo)
 {
		if (!*res)
			return -ENOMEM;

		ttm_resource_init(tbo, place, *res);
		(*res)->start = AMDGPU_BO_INVALID_OFFSET;
		return 0;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_preemptmgr.c b/drivers/gpu/drm/amd
========================================






========================================
Issue: Potential Buffer Overflow
Type: Buffer Overflow
File: drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
Line: 463

Description:
A potential buffer overflow has been detected in the function gfx_v9_4_2_wait_for_waves_assigned(). 
The function uses a fixed-size buffer of 256 bytes to store a formatted string, but does not implement proper bounds checking. 
The size of the string written to str depends on the values of constants CU_ID_MAX, SIMD_ID_MAX, and WAVE_ID_MAX, which are not taken 
into account when determining the buffer size. This could lead to a buffer overflow if the accumulated string length exceeds the allocated buffer size.

========================================
============= reference diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
@@ -460,7 +460,8 @@ static int gfx_v9_4_2_wait_for_waves_assigned(struct amdgpu_device *adev,
        char *str;
        int str_size;

-       str = kmalloc(256, GFP_KERNEL);
+       int max_buff_size = CU_ID_MAX * SIMD_ID_MAX * WAVE_ID_MAX * 64;
+       str = kmalloc(max_buff_size, GFP_KERNEL);
        if (!str)
                return;

@@ -470,7 +471,7 @@ static int gfx_v9_4_2_wait_for_waves_assigned(struct amdgpu_device *adev,

                for (se = 0; se < adev->gfx.config.max_shader_engines; se++)
                        for (cu = 0; cu < CU_ID_MAX; cu++) {
-                               memset(str, 0, 256);
+                               memset(str, 0, max_buff_size);
                                str_size = sprintf(str, "SE[%02d]CU[%02d]: ", se, cu);
                                for (simd = 0; simd < SIMD_ID_MAX; simd++) {
                                        str_size += sprintf(str + str_size, "[");
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c b/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
+++ b/drivers/gpu/drm/amd/amdgpu/gfx_v9_4_2.c
@@ -463,7 +463,7 @@ int gfx_v9_4_2_wait_for_waves_assigned(struct amdgpu_device *dev)
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
     *   }
     *   if (dev->pm->v9_4_2_wait_for_waves_assigned()) {
     *   return 0;
    
========================================






========================================
CID: 501947
Type: Buffer overflow
Severity: High
Checker: BUFFER_SIZE
Category: SECURE_CODING
File: drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
Function: vcn_v2_0_sw_init
Line: 169

Problem: 
Unbounded string copy when initializing VCN decoder ring name using sprintf

Abstract:
The code uses sprintf to write a fixed string into ring->name without size checking. 
Additionally, there appears to be a syntax error in the fix attempt, as the sizeof 
parameter is malformed. This could potentially overflow the destination buffer and 
corrupt adjacent memory.

Path:
 drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c:169
   sprintf(ring->name, "vcn_dec")

Details:
The VCN decoder ring initialization code copies a hardcoded string "vcn_dec" into 
the ring name buffer using sprintf without verifying the buffer size. While the 
source string is constant in this case, using unbounded string operations in 
kernel code is risky. Additionally, the attempted fix contains a syntax error in 
the sizeof usage.

Fix:
Replace with properly formatted snprintf call:
 snprintf(ring->name, sizeof(ring->name), "vcn_dec")
========================================
============= reference diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index bfd067e2d2f1..6419ab97d922 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ static int vcn_v2_0_sw_init(void *handle)
        ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
        ring->vm_hub = AMDGPU_MMHUB0(0);

-       sprintf(ring->name, "vcn_dec");
+       snprintf(ring->name, sizeof(ring->name), "vcn_dec");
        r = amdgpu_ring_init(adev, ring, 512, &adev->vcn.inst->irq, 0,
                             AMDGPU_RING_PRIO_DEFAULT, NULL);
        if (r)
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)
 {
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);
	 *ring->name = "vcn_dec";
	 *ring->doorbell_index = adev->doorbell_index.vcn.vcn_ring0_1 << 1;
	 *ring->vm_hub = AMDGPU_MMHUB0(0);```diff --git a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
+++ b/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
@@ -169,7 +169,7 @@ int amdgpu_ring_init(struct amdgpu_device *adev, struct amdgpu_device *ring, int width, int height)

========================================






========================================
CID: 487621
Type: Buffer overflow
Severity: High
Checker: BUFFER_SIZE
Category: RISKY_PROGRAMMING_PRACTICE
File: drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
Function: amdgpu_acpi_enumerate_xcc
Line: 1092

Problem:
Unbounded string operation using sprintf can cause buffer overflow

Abstract:
The code uses sprintf to write to buffer 'hid' without size checking. The sprintf 
operation could write beyond the buffer boundaries if the formatted output string 
exceeds the destination buffer size. This could corrupt adjacent memory and lead 
to system instability or security vulnerabilities.

Details:
The sprintf function is used to format a string containing "AMD" concatenated with 
a number. Since sprintf performs no bounds checking, if AMD_XCC_HID_START + id 
produces a large number, the resulting string could overflow the fixed-size 'hid' 
buffer. This occurs in the GPU driver's ACPI enumeration code which runs with 
kernel privileges.

Fix:
Replace sprintf with snprintf and specify the buffer size:
  snprintf(hid, sizeof(hid), "%s%d", "AMD", AMD_XCC_HID_START + id)

========================================
============= reference diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
index f85ace0384d2..10dfa3a37333 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
@@ -1089,7 +1089,7 @@ static int amdgpu_acpi_enumerate_xcc(void)
        xa_init(&numa_info_xa);

        for (id = 0; id < AMD_XCC_MAX_HID; id++) {
-               sprintf(hid, "%s%d", "AMD", AMD_XCC_HID_START + id);
+               snprintf(hid, sizeof(hid), "%s%d", "AMD", AMD_XCC_HID_START + id);
                acpi_dev = acpi_dev_get_first_match_dev(hid, NULL, -1);
                /* These ACPI objects are expected to be in sequential order. If
                 * one is not found, no need to check the rest.
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
@@ -1092,7 +1092,7 @@ int amdgpu_acpi_enumerate_xcc(int dev_id)
 {
		if (!acpi_dev) {
			return 0;
		}
		if (!acpi_dev) {
			return 0;
		}
		if (!acpi_dev) {
			return 0;
		}
		/* These ACPI objects are expected to be in sequential order. If
		 * one is not found, no need to check the rest.
		 */
		if (!acpi_dev) {
			return 0;
		}
		if (!acpi_dev) {
			return 0;
		}
		if (!acpi_dev) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the driver from accessing the ACPI objects
		 * when the system is under high-temperature or low-temperature
		 * conditions.
		 */
		if (dev->pm.thermal_protection || dev->pm.thermal_protection == -1) {
			return 0;
		}
		/* This is to prevent the
========================================






========================================
Issue: Resource Leak
File: drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
Function: amdgpu_cs_pass1
Line: 236

Description:
A memory resource allocated using kvmalloc_array() may not be freed if an error occurs during execution.
The function amdgpu_cs_pass1 allocates memory for chunk_array using kvmalloc_array(). 
However, if an error occurs after this allocation but before the function successfully completes, the allocated memory may not be freed, resulting in a resource leak.


========================================
============= reference diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -233,6 +233,7 @@ static int amdgpu_cs_pass1(struct amdgpu_cs_parser *p,
                size *= sizeof(uint32_t);
                if (copy_from_user(p->chunks[i].kdata, cdata, size)) {
                        ret = -EFAULT;
+                       i--;
                        goto free_partial_kdata;
                }
========================================
============= generated diff =============
```index 100644
-- drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -236,7 +236,7 @@ int amdgpu_cs_pass1(struct amdgpu_device *p)
         *   if (copy_from_user(p->chunks[i].kdata, cdata, size)) {
         *   goto free_partial_kdata;
         *   }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     }
         *   /* Assume the worst on the following checks */
         *   ret = -EINVAL;
         *   switch (p->chunks[i].chunk_id) {
         *     return -EINVAL;
         *     switch (p->chunks[i].chunk_id) {
         *     return -EINVAL
========================================






========================================
CID: 1234567
Type: Buffer overflow
Category: BUFFER_OVERFLOW
Classification: Bad use of string function
Severity: High
Certainty: Absolute
Status: New
Function: amdgpu_atombios_i2c_init
File: drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
Line: 150

Issue:
Unbounded sprintf can cause buffer overflow. The code uses sprintf() without size limits to write into buffer 'stmp', which could lead to buffer overflow if the formatted string exceeds the buffer size.

Description:
The function amdgpu_atombios_i2c_init() uses sprintf() to format a hexadecimal value into a string buffer 'stmp' without checking if the resulting string will fit in the destination buffer. This could lead to a buffer overflow if i2c.i2c_id generates a string longer than the size of stmp.

Use snprintf instead
========================================
============= reference diff =============
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
index 0c8975ac5af9..a6245ec89453 100644
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
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c
@@ -150,7 +150,7 @@ int amdgpu_atombios_i2c_init(struct amdgpu_device *adev)
         *   if (i2c.valid) {
         *     sprintf(stmp, "0x%x", i2c.i2c_id);
         *     adev->i2c_bus[i] = amdgpu_i2c_create(adev_to_drm(adev), &i2c, stmp);
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));
         *     }
         *     gpio = (ATOM_GPIO_I2C_ASSIGMENT *)
         *         ((u8 *)gpio + sizeof(ATOM_GPIO_I2C_ASSIGMENT));

========================================






========================================
File:       drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
Function:   amdgpu_gem_object_create
Line: 116
Type:       Null Pointer Dereference
Category:   Error Handling Issues
CID:        12000
Impact:     High

Description:
------------
The function dereferences the pointer adev and resv without first checking if they are NULL. 
If either pointer is NULL, dereferencing them (e.g. adev->dev or resv->lock) will cause a crash.


========================================
============= reference diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_gem.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_gem.c
@@ -101,6 +101,8 @@ int amdgpu_gem_object_create(struct amdgpu_device *adev, unsigned long size,
                             struct dma_resv *resv,
                             struct drm_gem_object **obj, int8_t xcp_id_plus1)
 {
+       if (!adev || !resv)
+           return VM_FAULT_SIGSEGV;
        struct amdgpu_bo *bo;
        struct amdgpu_bo_user *ubo;
        struct amdgpu_bo_param bp;
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING_MAX_IBS) {
			return -EINVAL;
		}
		++(num_ibs[r]);```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -116,7 +116,7 @@ int amdgpu_gem_object_create(struct amdgpu_device *p, struct amdgpu_device *p, struct amdgpu_device *p)
{
		if (p->gang_leader_idx == -1) {
			p->gang_leader_idx = 0;
			if (p->ip_type == AMDGPU_RING_MAX_IBS) {
				p->gang_leader_idx = -1;
			}
		++(p->gang_leader_idx);
		p->gang_leader_idx = r;
		if (p->ip_type == AMDGPU_RING
========================================






========================================
Issue: Potential Buffer Overflow

CID: 1024
Severity: High
Type: Security
Category: Buffer Overflow
File: drivers/gpu/drm/amd/amdgpu/atombios_dp.c
Function: amdgpu_atombios_dp_get_dpcd
Line: 359

Description:
A potential buffer overflow vulnerability was present in the function amdgpu_atombios_dp_get_dpcd.
The issue arises from the call to memcpy(dig_connector->dpcd, msg, DP_DPCD_SIZE);, 
where the size of DP_DPCD_SIZE is not validated against the size of the destination buffer dig_connector->dpcd. 
If DP_DPCD_SIZE exceeds the size of dig_connector->dpcd, it could result in memory corruption.
========================================
============= reference diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/atombios_dp.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/atombios_dp.c
index 622634c..3a2a16f 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/atombios_dp.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/atombios_dp.c
@@ -356,6 +356,9 @@ int amdgpu_atombios_dp_get_dpcd(struct amdgpu_connector *amdgpu_connector)
        ret = drm_dp_dpcd_read(&amdgpu_connector->ddc_bus->aux, DP_DPCD_REV,
                               msg, DP_DPCD_SIZE);
        if (ret == DP_DPCD_SIZE) {
+               if (DP_DPCD_SIZE > sizeof(dig_connector->dpcd)) {
+                       return;
+               }
                memcpy(dig_connector->dpcd, msg, DP_DPCD_SIZE);

                DRM_DEBUG_KMS("DPCD: %*ph\n", (int)sizeof(dig_connector->dpcd),
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/atombios_dp.c b/drivers/gpu/drm/amd/amdgpu/atombios_dp.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/atombios_dp.c
+++ b/drivers/gpu/drm/amd/amdgpu/atombios_dp.c
@@ -359,7 +359,7 @@ int amdgpu_atombios_dp_get_dpcd(struct amdgpu_device *amdgpu_device)
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
         *   if (dig_connector->dpcd->size > DP_DPCD_SIZE) {
-         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
+         *   return -1 if the size of the destination buffer is less than DP_DPCD_SIZE
        
========================================






========================================
CID: 10000
Classification: NULL_RETURNS
Function: aldebaran_mode2_prepare_hwcontext 
File: drivers/gpu/drm/amd/amdgpu/aldebaran.c
Line: 108

Description:
The function 'aldebaran_mode2_prepare_hwcontext' dereferences 'reset_ctl->handle' without first 
checking if 'reset_ctl' or 'reset_ctl->handle' is NULL. This could lead to a null pointer dereference 
if either 'reset_ctl' or 'reset_ctl->handle' is NULL when the function is called.



========================================
============= reference diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c
index b0f95a7..35f4479 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/aldebaran.c
@@ -105,6 +105,9 @@ aldebaran_mode2_prepare_hwcontext(struct amdgpu_reset_control *reset_ctl,
                                  struct amdgpu_reset_context *reset_context)
 {
        int r = 0;
+       if (!reset->ctl || !reset_ctl->handle) {
+               return NULL;
+       }
        struct amdgpu_device *adev = (struct amdgpu_device *)reset_ctl->handle;

        dev_dbg(adev->dev, "Aldebaran prepare hw context\n");
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/aldebaran.c b/drivers/gpu/drm/amd/amdgpu/aldebaran.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/aldebaran.c
+++ b/drivers/gpu/drm/amd/amdgpu/aldebaran.c
@@ -108,7 +108,7 @@ int aldebaran_mode2_prepare_hwcontext(struct amdgpu_reset_control *reset_ctl,
-        if (!amdgpu_sriov_vf(adev)) {
-        r = aldebaran_mode2_suspend_ip(adev);
+        if (!amdgpu_sriov_vf(adev)) {
+        r = aldebaran_mode2_suspend_ip(adev);
        	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);

	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
		if (!amdgpu_sriov_vf(adev))
			r = aldebaran_mode2_suspend_ip(adev);
		else
			r = aldebaran_mode2_suspend_ip(adev);
	/* Don't
========================================






========================================
File:       drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
Function:   amdgpu_cs_job_idx
Line: 80
Type:       Null Pointer Dereference
Category:   Error Handling Issues
CID:        12000
Impact:     High

Description:
------------
A potential null pointer dereference issue has been identified in the `amdgpu_cs_job_idx` function. 
If the `amdgpu_cs_parser *p` or `drm_amdgpu_cs_chunk_ib *chunk_ib` is NULL, accessing members of these 
structures without validation may lead to undefined behavior and potential system instability.

========================================
============= reference diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -73,6 +73,8 @@ static int amdgpu_cs_parser_init(struct amdgpu_cs_parser *p,
 static int amdgpu_cs_job_idx(struct amdgpu_cs_parser *p,
                             struct drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
+       if (p == NULL || chunk_ib == NULL)
+           return -EINVAL;
        struct drm_sched_entity *entity;
        unsigned int i;
        int r;
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->ip_type == 'power' || chunk_ib->ip_instance == NULL) {
			return -1;
		}
		if (chunk_ib->ring->power_state == DRM_AMDGPU_CS_POWER_STATE_SLEEP) {
			return 0;
		}
		return 1;
	}
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
index 12000..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c
@@ -80,7 +80,7 @@ int amdgpu_cs_job_idx(drm_amdgpu_cs_chunk_ib *chunk_ib)
 {
		if (chunk_ib->
========================================






========================================
Type: BUFFER_OVERFLOW
File: drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
Function: amdgpu_atif_get_notification_params
Line: 303

Description: Potential buffer overflow in memcpy() operation

There is a potential buffer overflow in the call to memcpy(). The size argument
to memcpy() is derived from untrusted input (info->buffer.pointer) and may exceed
the size of the destination buffer.

========================================
============= reference diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
@@ -300,6 +300,10 @@ static int amdgpu_atif_get_notification_params(struct amdgpu_atif *atif)

        memset(&params, 0, sizeof(params));
        size = min(sizeof(params), size);
+       size_t safe_size = min(sizeof(params), size);
+       if (safe_size > info->buffer.length) {
+               return -EINVAL;
+       }
        memcpy(&params, info->buffer.pointer, size);

        DRM_DEBUG_DRIVER("SYSTEM_PARAMS: mask = %#x, flags = %#x\n",
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c
@@ -303,7 +303,7 @@ int amdgpu_atif_get_notification_params(struct amdgpu_device *dev)
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value, so we need to make sure the buffer is not too small
         *   to mask the value
========================================






========================================
Issue: Potential Memory Leak
File: drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c
Line: 547

Description:
The function create_sg_table allocates memory for buffer sg using but does not free this memory in all code paths. The allocated memory is returned to the caller without being freed.


========================================
============= reference diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c
@@ -544,6 +544,10 @@ static struct sg_table *create_sg_table(uint64_t addr, uint32_t size)
 #ifdef CONFIG_NEED_SG_DMA_LENGTH
        sg->sgl->dma_length = size;
 #endif
+    if (!sg) {
+        pr_warn("sg table buffer is NULL");
+        return NULL;
+    }
     return sg;
}
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gpuvm.c
@@ -547,3 +547,3 @@ int amdgpu_amdkfd_gpuvm(struct amdgpu_device *sgl)
 {
-     *   if (sgl->sgl->length < 1024) {
-     *   allocate memory for buffer sg
-     *   if (sgl->sgl->length < 1024) {
-     *   allocate memory for buffer sg
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024) {
+     *   allocate memory for buffer sg
+     *   if (sgl->sgl->length < 1024)
========================================






========================================
Integer Overflow in vi_read_bios_from_rom
CID: 2002

Severity: High
Type: Integer Overflow
File: drivers/gpu/drm/amd/amdgpu/vi.c
Line: 651
Location: vi_read_bios_from_rom function
Description
An integer overflow risk has been identified in the vi_read_bios_from_rom function. 
The variable length_dw, defined as a u8, is assigned the result of an ALIGN macro operation, 
which can yield values exceeding 255 when certain length_bytes inputs are provided.

u32 length_dw = ALIGN(length_bytes, 4);


========================================
============= reference diff =============
diff --git a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/vi.c b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/vi.c
index d28d6b9..00851a4 100644
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/vi.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/vi.c
@@ -648,7 +648,7 @@ static bool vi_read_bios_from_rom(struct amdgpu_device *adev,
                return false;

        dw_ptr = (u32 *)bios;
-       u8 length_dw = ALIGN(length_bytes, 4);
+       u32 length_dw = ALIGN(length_bytes, 4);
        /* take the smc lock since we are using the smc index */
        spin_lock_irqsave(&adev->smc_idx_lock, flags);
        /* set rom index to 0 */
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/vi.c b/drivers/gpu/drm/amd/amdgpu/vi.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vi.c
+++ b/drivers/gpu/drm/amd/amdgpu/vi.c
@@ -651,7 +651,7 @@ int vi_read_bios_from_rom(struct amdgpu_device *adev)
         *   if (adev->flags & AMD_IS_APU)
         *   return false;
+
+    /* take the smc lock since we are using the smc index */
+    spin_lock_irqsave(&adev->smc_idx_lock, flags);
+    /* set rom index to 0 */
+    WREG32(mmSMC_IND_INDEX_11, ixROM_INDEX);
+    WREG32(mmSMCIndData11, 0);

```diff --git a/drivers/gpu/drm/amd/amdgpu/vi.c b/drivers/gpu/drm/amd/amdgpu/vi.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vi.c
+++ b/drivers/gpu/drm/amd/amdgpu/vi.c
@@ -651,7 +651,7 @@ int vi_read_bios_from_rom(struct amdgpu_device *adev)
         *   if (adev->flags & AMD_IS_APU)
         *   return false;
+
+    /* take the smc lock since we are using the smc index */
+    spin_lock_irqsave(&adev->smc_idx_lock, flags);
+    /* set rom index to 0 */
+    WREG32(mmSMCIndData11, 0);

```diff --git a/drivers/gpu/drm/amd/amdgpu/vi.c b/drivers/gpu/drm/amd/amdgpu/vi.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vi.c
+++ b/drivers/gpu/drm/amd/amdgpu/vi.c
@@ -651,7 +651,7 @@ int vi_read_bios_from_rom(struct amdgpu_device *adev)
         *   if (adev->flags & AMD_IS_APU)
         *   return false;
+
+    /* take the smc lock since we are using the smc index */
+    spin_lock_irqsave(&adev->smc_idx_lock, flags);
+    /* set rom index to 0 */
+    WREG32(mmSMCIndData11, 0);
========================================






========================================
Issue: Lack of Boundary Checks
Type: BUFFER_OVERFLOW
File: drivers/gpu/drm/amd/amdgpu/vi.c
Line: 659

Description:
The function vi_read_bios_from_rom lacks proper boundary checks when reading data into the bios buffer. 
The function calculates the number of dwords to read based on the input length_bytes, but it doesn't verify 
if this calculated length exceeds the actual allocated size of the bios buffer. 
This can lead to a buffer overflow, potentially causing memory corruption or security vulnerabilities.


========================================
============= reference diff =============
--- a/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/vi.c
+++ b/coverity/dataset/raw_data/code/drivers/gpu/drm/amd/amdgpu/vi.c
@@ -656,6 +656,8 @@ static bool vi_read_bios_from_rom(struct amdgpu_device *adev,
        WREG32(mmSMC_IND_DATA_11, 0);
        /* set index to data for continous read */
        WREG32(mmSMC_IND_INDEX_11, ixROM_DATA);
+       if (length_dw * 4 > adev->bios_size)
+               return false;
        for (i = 0; i < length_dw; i++)
                dw_ptr[i] = RREG32(mmSMC_IND_DATA_11);
        spin_unlock_irqrestore(&adev->smc_idx_lock, flags);
========================================
============= generated diff =============
```diff --git a/drivers/gpu/drm/amd/amdgpu/vi.c b/drivers/gpu/drm/amd/amdgpu/vi.c
index 1234567..89abcdef 100644
--- a/drivers/gpu/drm/amd/amdgpu/vi.c
+++ b/drivers/gpu/drm/amd/amdgpu/vi.c
@@ -659,7 +659,7 @@ int amdgpu_vi_read_bios_from_rom(int length_bytes)
 {
     if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
         dw_ptr[0] = RREG32(mmSMCIndData11, ixROMData);
         spin_unlock_irqrestore(&adev->smc_idx_lock, flags);
+        if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length_bytes > ADEVTW_MSMC_IND_DATA_11_BIOS_BUFFER_SIZE) {
+                if (length
========================================



