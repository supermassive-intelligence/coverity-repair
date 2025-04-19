Function name: aldebaran_reset_init
Input: 


int aldebaran_reset_init(struct amdgpu_device *adev)
{
	struct amdgpu_reset_control *reset_ctl;

	reset_ctl = kzalloc(sizeof(*reset_ctl), GFP_KERNEL);
	if (!reset_ctl)
		return -ENOMEM;

	reset_ctl->handle = adev;
	reset_ctl->async_reset = aldebaran_async_reset;
	reset_ctl->active_reset = AMD_RESET_METHOD_NONE;
	reset_ctl->get_reset_handler = aldebaran_get_reset_handler;

	INIT_WORK(&reset_ctl->reset_work, reset_ctl->async_reset);
	/* Only mode2 is handled through reset control now */
	reset_ctl->reset_handlers = &aldebaran_rst_handlers;

	adev->reset_cntl = reset_ctl;

	return 0;
}

Output: 
int aldebaran_reset_init(struct amdgpu_device *adev)
{
	struct amdgpu_reset_control *reset_ctl;

	reset_ctl = kzalloc(sizeof(*reset_ctl), GFP_KERNEL);
	if (!reset_ctl)
		return -ENOMEM;

	if (!adev) {
		kfree(reset_ctl);
		return -EINVAL;
	}

	reset_ctl->handle = adev;
	reset_ctl->async_reset = aldebaran_async_reset;
	reset_ctl->active_reset = AMD_RESET_METHOD_NONE;
	reset_ctl->get_reset_handler = aldebaran_get_reset_handler;

	if (!reset_ctl->async_reset) {
		kfree(reset_ctl);
		return -EINVAL;
	}

	INIT_WORK(&reset_ctl->reset_work, reset_ctl->async_reset);
	/* Only mode2 is handled through reset control now */
	reset_ctl->reset_handlers = &aldebaran_rst_handlers;

	if (adev->reset_cntl) {
		kfree(adev->reset_cntl);
	}

	adev->reset_cntl = reset_ctl;

	return 0;
}