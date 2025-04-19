Function name: aldebaran_is_mode2_default
Input: 


static bool aldebaran_is_mode2_default(struct amdgpu_reset_control *reset_ctl)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)reset_ctl->handle;

	if ((amdgpu_ip_version(adev, MP1_HWIP, 0) == IP_VERSION(13, 0, 2) &&
	     adev->gmc.xgmi.connected_to_cpu))
		return true;

	return false;
}

Output: 
static bool aldebaran_is_mode2_default(struct amdgpu_reset_control *reset_ctl)
{
	struct amdgpu_device *adev = (struct amdgpu_device *)reset_ctl->handle;

	if (adev != NULL && reset_ctl != NULL) {
		if ((amdgpu_ip_version(adev, MP1_HWIP, 0) == IP_VERSION(13, 0, 2) &&
		     adev->gmc.xgmi.connected_to_cpu))
			return true;
	}

	return false;
}