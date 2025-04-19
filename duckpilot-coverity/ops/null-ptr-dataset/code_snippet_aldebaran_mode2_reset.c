Function name: aldebaran_mode2_reset
Input: 


static int aldebaran_mode2_reset(struct amdgpu_device *adev)
{
	/* disable BM */
	pci_clear_master(adev->pdev);
	adev->asic_reset_res = amdgpu_dpm_mode2_reset(adev);
	return adev->asic_reset_res;
}

Output: 
static int aldebaran_mode2_reset(struct amdgpu_device *adev)
{
	if (adev == NULL) {
		return -EINVAL;
	}

	if (adev->pdev == NULL) {
		return -EINVAL;
	}

	pci_clear_master(adev->pdev);
	adev->asic_reset_res = amdgpu_dpm_mode2_reset(adev);
	return adev->asic_reset_res;
}