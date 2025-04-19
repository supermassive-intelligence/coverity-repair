Function name: for
Input: 


	for (i = 0; i < adev->num_ip_blocks; i++) {
		if (!(adev->ip_blocks[i].version->type ==
			      AMD_IP_BLOCK_TYPE_GFX ||
		      adev->ip_blocks[i].version->type ==
			      AMD_IP_BLOCK_TYPE_SDMA ||
		      adev->ip_blocks[i].version->type ==
			      AMD_IP_BLOCK_TYPE_COMMON))
			continue;

		if (adev->ip_blocks[i].version->funcs->late_init) {
			r = adev->ip_blocks[i].version->funcs->late_init(
				(void *)adev);
			if (r) {
				dev_err(adev->dev,
					"late_init of IP block <%s> failed %d after reset\n",
					adev->ip_blocks[i].version->funcs->name,
					r);
				return r;
			}
		}
		adev->ip_blocks[i].status.late_initialized = true;
	}

Output: 
for (i = 0; i < adev->num_ip_blocks; i++) {
	if (!(adev->ip_blocks[i].version && adev->ip_blocks[i].version->type ==
			      AMD_IP_BLOCK_TYPE_GFX ||
		      adev->ip_blocks[i].version && adev->ip_blocks[i].version->type ==
			      AMD_IP_BLOCK_TYPE_SDMA ||
		      adev->ip_blocks[i].version && adev->ip_blocks[i].version->type ==
			      AMD_IP_BLOCK_TYPE_COMMON))
		continue;

	if (adev->ip_blocks[i].version && adev->ip_blocks[i].version->funcs &&
	    adev->ip_blocks[i].version->funcs->late_init) {
		r = adev->ip_blocks[i].version->funcs->late_init(
			(void *)adev);
		if (r) {
			dev_err(adev->dev,
				"late_init of IP block <%s> failed %d after reset\n",
				adev->ip_blocks[i].version->funcs->name,
				r);
			return r;
		}
	}
	adev->ip_blocks[i].status.late_initialized = true;
}