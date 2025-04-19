Function name: for_each_handler
Input: 


	for_each_handler(i, handler, reset_ctl)	{
		if (handler->reset_method == reset_ctl->active_reset) {
			dev_dbg(adev->dev, "Resetting device\n");
			handler->do_reset(adev);
			break;
		}
	}

Output: 
for_each_handler(i, handler, reset_ctl) {
	if (handler && handler->reset_method == reset_ctl->active_reset) {
		dev_dbg(adev->dev, "Resetting device\n");
		if (handler->do_reset) {
			handler->do_reset(adev);
		}
		break;
	}
}