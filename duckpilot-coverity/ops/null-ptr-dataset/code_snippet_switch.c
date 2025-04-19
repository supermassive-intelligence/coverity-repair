Function name: switch
Input: 

		switch (ucode->ucode_id) {
		case AMDGPU_UCODE_ID_SDMA0:
		case AMDGPU_UCODE_ID_SDMA1:
		case AMDGPU_UCODE_ID_SDMA2:
		case AMDGPU_UCODE_ID_SDMA3:
		case AMDGPU_UCODE_ID_SDMA4:
		case AMDGPU_UCODE_ID_SDMA5:
		case AMDGPU_UCODE_ID_SDMA6:
		case AMDGPU_UCODE_ID_SDMA7:
		case AMDGPU_UCODE_ID_CP_MEC1:
		case AMDGPU_UCODE_ID_CP_MEC1_JT:
		case AMDGPU_UCODE_ID_RLC_RESTORE_LIST_CNTL:
		case AMDGPU_UCODE_ID_RLC_RESTORE_LIST_GPM_MEM:
		case AMDGPU_UCODE_ID_RLC_RESTORE_LIST_SRM_MEM:
		case AMDGPU_UCODE_ID_RLC_G:
			ucode_list[ucode_count++] = ucode;
			break;
		default:
			break;
		}

Output: 
switch (ucode->ucode_id) {
	case AMDGPU_UCODE_ID_SDMA0:
	case AMDGPU_UCODE_ID_SDMA1:
	case AMDGPU_UCODE_ID_SDMA2:
	case AMDGPU_UCODE_ID_SDMA3:
	case AMDGPU_UCODE_ID_SDMA4:
	case AMDGPU_UCODE_ID_SDMA5:
	case AMDGPU_UCODE_ID_SDMA6:
	case AMDGPU_UCODE_ID_SDMA7:
	case AMDGPU_UCODE_ID_CP_MEC1:
	case AMDGPU_UCODE_ID_CP_MEC1_JT:
	case AMDGPU_UCODE_ID_RLC_RESTORE_LIST_CNTL:
	case AMDGPU_UCODE_ID_RLC_RESTORE_LIST_GPM_MEM:
	case AMDGPU_UCODE_ID_RLC_RESTORE_LIST_SRM_MEM:
	case AMDGPU_UCODE_ID_RLC_G:
		if (ucode != NULL && ucode_count < MAX_UCODES) {
			ucode_list[ucode_count++] = ucode;
		}
		break;
	default:
		break;
}