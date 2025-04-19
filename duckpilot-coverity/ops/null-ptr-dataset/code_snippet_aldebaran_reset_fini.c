Function name: aldebaran_reset_fini
Input: 


int aldebaran_reset_fini(struct amdgpu_device *adev)
{
	kfree(adev->reset_cntl);
	adev->reset_cntl = NULL;
	return 0;
}

Output: 
int aldebaran_reset_fini(struct amdgpu_device *adev)
{
	if (adev == NULL) {
		return -EINVAL;
	}
	if (adev->reset_cntl != NULL) {
		kfree(adev->reset_cntl);
	}
	adev->reset_cntl = NULL;
	return 0;
}