Function name: aldebaran_get_reset_handler
Input: 


static struct amdgpu_reset_handler *
aldebaran_get_reset_handler(struct amdgpu_reset_control *reset_ctl,
			    struct amdgpu_reset_context *reset_context)
{
	struct amdgpu_reset_handler *handler;
	struct amdgpu_device *adev = (struct amdgpu_device *)reset_ctl->handle;
	int i;

	if (reset_context->method == AMD_RESET_METHOD_NONE) {
		if (aldebaran_is_mode2_default(reset_ctl))
			reset_context->method = AMD_RESET_METHOD_MODE2;
		else
			reset_context->method = amdgpu_asic_reset_method(adev);
	}

	if (reset_context->method != AMD_RESET_METHOD_NONE) {
		dev_dbg(adev->dev, "Getting reset handler for method %d\n",
			reset_context->method);
		for_each_handler(i, handler, reset_ctl) {
			if (handler->reset_method == reset_context->method)
				return handler;
		}
	}

	dev_dbg(adev->dev, "Reset handler not found!\n");

	return NULL;
}

Output: 
static struct amdgpu_reset_handler *
aldebaran_get_reset_handler(struct amdgpu_reset_control *reset_ctl,
			    struct amdgpu_reset_context *reset_context)
{
	struct amdgpu_reset_handler *handler;
	struct amdgpu_device *adev = (struct amdgpu_device *)reset_ctl->handle;
	int i;

	if (reset_context->method == AMD_RESET_METHOD_NONE) {
		if (aldebaran_is_mode2_default(reset_ctl))
			reset_context->method = AMD_RESET_METHOD_MODE2;
		else
			reset_context->method = amdgpu_asic_reset_method(adev);
	}

	if (reset_context->method != AMD_RESET_METHOD_NONE) {
		dev_dbg(adev->dev, "Getting reset handler for method %d\n",
			reset_context->method);
		if (reset_ctl != NULL && reset_ctl->handlers != NULL) {
			for_each_handler(i, handler, reset_ctl) {
				if (handler != NULL && handler->reset_method == reset_context->method)
					return handler;
			}
		}
	}

	dev_dbg(adev->dev, "Reset handler not found!\n");

	return NULL;
}