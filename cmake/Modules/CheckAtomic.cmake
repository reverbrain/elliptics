# Check whether libatomic or __sync are supported
# Sets variables:
#  HAVE_SYNC_ATOMIC_SUPPORT - whether __sync support is available

include(CheckCSourceCompiles)

check_c_source_compiles("int main()
{
    long var;
    __sync_add_and_fetch(&var, 1);
    return 0;
}" HAVE_SYNC_ATOMIC_SUPPORT)
if (HAVE_SYNC_ATOMIC_SUPPORT)
    add_definitions(-DHAVE_SYNC_ATOMIC_SUPPORT=1)
endif()

message(STATUS "__sync support: ${HAVE_SYNC_ATOMIC_SUPPORT}")
