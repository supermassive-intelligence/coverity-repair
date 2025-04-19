Function name: if
Input: 

			if (r) {
				dev_err(tmp_adev->dev,
					"ib ring test failed (%d).\n", r);
				r = -EAGAIN;
				tmp_adev->asic_reset_res = r;
				goto end;
			}

Output: 
if (tmp_adev && tmp_adev->dev && r) {
    dev_err(tmp_adev->dev,
            "ib ring test failed (%d).\n", r);
    r = -EAGAIN;
    tmp_adev->asic_reset_res = r;
    goto end;
}