link_directories(${PROJECT_BINARY_DIR}/common ${PROJECT_BINARY_DIR}/hfs ${PROJECT_BINARY_DIR}/dmg)

# hdutil (ls/cat/extract on a mounted HFS+/DMG volume) duplicates what
# macOS's own native `hdiutil attach` + standard Unix tools already do --
# skip building it there.
IF(NOT APPLE)
	add_executable(hdutil hdutil.c)

	target_link_libraries (hdutil dmg hfs common)

	install(TARGETS hdutil DESTINATION .)
ENDIF(NOT APPLE)

