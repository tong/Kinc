#include <kinc/backend/graphics4/rendertarget.h>

#include <kinc/graphics4/rendertarget.h>
#include <kinc/graphics5/commandlist.h>
#include <kinc/log.h>

extern kinc_g5_command_list_t commandList;

void kinc_g4_render_target_init_with_multisampling(kinc_g4_render_target_t *render_target, int width, int height, kinc_g4_render_target_format_t format,
                                                   int depthBufferBits, int stencilBufferBits, int samples_per_pixel) {
	kinc_g5_render_target_init_with_multisampling(&render_target->impl._renderTarget, width, height, (kinc_g5_render_target_format_t)format, depthBufferBits,
	                                              stencilBufferBits, samples_per_pixel);
	render_target->texWidth = render_target->width = width;
	render_target->texHeight = render_target->height = height;
	render_target->impl.state = KINC_INTERNAL_RENDER_TARGET_STATE_RENDER_TARGET;
}

void kinc_g4_render_target_init_cube_with_multisampling(kinc_g4_render_target_t *render_target, int cubeMapSize, kinc_g4_render_target_format_t format,
                                                        int depthBufferBits, int stencilBufferBits, int samples_per_pixel) {
	kinc_g5_render_target_init_cube_with_multisampling(&render_target->impl._renderTarget, cubeMapSize, (kinc_g5_render_target_format_t)format, depthBufferBits,
	                                                   stencilBufferBits, samples_per_pixel);
}

void kinc_g4_render_target_destroy(kinc_g4_render_target_t *render_target) {
	kinc_g5_render_target_destroy(&render_target->impl._renderTarget);
}

void kinc_g4_render_target_use_color_as_texture(kinc_g4_render_target_t *render_target, kinc_g4_texture_unit_t unit) {
	if (render_target->impl.state != KINC_INTERNAL_RENDER_TARGET_STATE_TEXTURE) {
		kinc_g5_command_list_render_target_to_texture_barrier(&commandList, &render_target->impl._renderTarget);
		render_target->impl.state = KINC_INTERNAL_RENDER_TARGET_STATE_TEXTURE;
	}
	kinc_g5_render_target_use_color_as_texture(&render_target->impl._renderTarget, unit.impl._unit);
}

void kinc_g4_render_target_use_depth_as_texture(kinc_g4_render_target_t *render_target, kinc_g4_texture_unit_t unit) {
	if (render_target->impl.state != KINC_INTERNAL_RENDER_TARGET_STATE_TEXTURE) {
		kinc_g5_command_list_render_target_to_texture_barrier(&commandList, &render_target->impl._renderTarget);
		render_target->impl.state = KINC_INTERNAL_RENDER_TARGET_STATE_TEXTURE;
	}
	kinc_g5_render_target_use_depth_as_texture(&render_target->impl._renderTarget, unit.impl._unit);
}

void kinc_g4_render_target_set_depth_stencil_from(kinc_g4_render_target_t *render_target, kinc_g4_render_target_t *source) {
	kinc_g5_render_target_set_depth_stencil_from(&render_target->impl._renderTarget, &source->impl._renderTarget);
}

void kinc_g4_render_target_get_pixels(kinc_g4_render_target_t *render_target, uint8_t *data) {
	kinc_g5_command_list_get_render_target_pixels(&commandList, &render_target->impl._renderTarget, data);
}

void kinc_g4_render_target_generate_mipmaps(kinc_g4_render_target_t *render_target, int levels) {}
