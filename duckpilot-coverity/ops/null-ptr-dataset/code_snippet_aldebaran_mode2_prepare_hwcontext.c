Function name: aldebaran_mode2_prepare_hwcontext
Input: 


static int
aldebaran_mode2_prepare_hwcontext(struct amdgpu_reset_control *reset_ctl,
				  struct amdgpu_reset_context *reset_context)
{
	int r = 0;
	struct amdgpu_device *adev = (struct amdgpu_device *)reset_ctl->handle;

	dev_dbg(adev->dev, "Aldebaran prepare hw context\n");
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
	if (!amdgpu_sriov_vf(adev))
		r = aldebaran_mode2_suspend_ip(adev);

	return r;
}

Output: 
static int
aldebaran_mode2_prepare_hwcontext(struct amdgpu_reset_control *reset_ctl,
				  struct amdgpu_reset_context *reset_context)
{
	int r = 0;
	struct amdgpu_device *adev = (struct amdgpu_device *)reset_ctl->handle;

	if (adev == NULL) {
		dev_err(adev->dev, "Invalid handle in reset control\n");
		return -EINVAL;
	}

	dev_dbg(adev->dev, "Aldebaran prepare hw context\n");
	/* Don't suspend on bare metal if we are not going to HW reset the ASIC */
	if (!amdgpu_sriov_vf(adev))
		r = aldebaran_mode2_suspend_ip(adev);

	return r;
}