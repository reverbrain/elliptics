set(SOURCES
	HonestCommandHandler.cc
	HonestCommandHandlerAdaptee.cc
	UncomplicatedHandler.cc
	CallbackUncomplicatedHandler.cc
	ModuleRegistration.cc
	module_backend_implementation.cc
)
add_library(module_backend_implementation MODULE ${SOURCES})
set_target_properties(module_backend_implementation PROPERTIES PREFIX "")
set_target_properties(module_backend_implementation PROPERTIES COMPILE_FLAGS "-std=c++0x")
