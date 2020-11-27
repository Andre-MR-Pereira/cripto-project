# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mnt/c/Users/ASUS/documents/faculdade/4_ano/1ºsemestre/cripto/cripto-project

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/c/Users/ASUS/Documents/faculdade/4_ano/1ºsemestre/Cripto/cripto-project

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/local/bin/cmake --regenerate-during-build -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "No interactive CMake dialog available..."
	/usr/local/bin/cmake -E echo No\ interactive\ CMake\ dialog\ available.
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /mnt/c/Users/ASUS/Documents/faculdade/4_ano/1ºsemestre/Cripto/cripto-project/CMakeFiles /mnt/c/Users/ASUS/Documents/faculdade/4_ano/1ºsemestre/Cripto/cripto-project/CMakeFiles/progress.marks
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /mnt/c/Users/ASUS/Documents/faculdade/4_ano/1ºsemestre/Cripto/cripto-project/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named cripto_project

# Build rule for target.
cripto_project: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 cripto_project
.PHONY : cripto_project

# fast build rule for target.
cripto_project/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/cripto_project.dir/build.make CMakeFiles/cripto_project.dir/build
.PHONY : cripto_project/fast

lib/assets/encryptions/database_encryption.o: lib/assets/encryptions/database_encryption.cpp.o

.PHONY : lib/assets/encryptions/database_encryption.o

# target to build an object file
lib/assets/encryptions/database_encryption.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/cripto_project.dir/build.make CMakeFiles/cripto_project.dir/lib/assets/encryptions/database_encryption.cpp.o
.PHONY : lib/assets/encryptions/database_encryption.cpp.o

lib/assets/encryptions/database_encryption.i: lib/assets/encryptions/database_encryption.cpp.i

.PHONY : lib/assets/encryptions/database_encryption.i

# target to preprocess a source file
lib/assets/encryptions/database_encryption.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/cripto_project.dir/build.make CMakeFiles/cripto_project.dir/lib/assets/encryptions/database_encryption.cpp.i
.PHONY : lib/assets/encryptions/database_encryption.cpp.i

lib/assets/encryptions/database_encryption.s: lib/assets/encryptions/database_encryption.cpp.s

.PHONY : lib/assets/encryptions/database_encryption.s

# target to generate assembly for a file
lib/assets/encryptions/database_encryption.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/cripto_project.dir/build.make CMakeFiles/cripto_project.dir/lib/assets/encryptions/database_encryption.cpp.s
.PHONY : lib/assets/encryptions/database_encryption.cpp.s

lib/assets/examples/test/test_run.o: lib/assets/examples/test/test_run.cpp.o

.PHONY : lib/assets/examples/test/test_run.o

# target to build an object file
lib/assets/examples/test/test_run.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/cripto_project.dir/build.make CMakeFiles/cripto_project.dir/lib/assets/examples/test/test_run.cpp.o
.PHONY : lib/assets/examples/test/test_run.cpp.o

lib/assets/examples/test/test_run.i: lib/assets/examples/test/test_run.cpp.i

.PHONY : lib/assets/examples/test/test_run.i

# target to preprocess a source file
lib/assets/examples/test/test_run.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/cripto_project.dir/build.make CMakeFiles/cripto_project.dir/lib/assets/examples/test/test_run.cpp.i
.PHONY : lib/assets/examples/test/test_run.cpp.i

lib/assets/examples/test/test_run.s: lib/assets/examples/test/test_run.cpp.s

.PHONY : lib/assets/examples/test/test_run.s

# target to generate assembly for a file
lib/assets/examples/test/test_run.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/cripto_project.dir/build.make CMakeFiles/cripto_project.dir/lib/assets/examples/test/test_run.cpp.s
.PHONY : lib/assets/examples/test/test_run.cpp.s

main.o: main.cpp.o

.PHONY : main.o

# target to build an object file
main.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/cripto_project.dir/build.make CMakeFiles/cripto_project.dir/main.cpp.o
.PHONY : main.cpp.o

main.i: main.cpp.i

.PHONY : main.i

# target to preprocess a source file
main.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/cripto_project.dir/build.make CMakeFiles/cripto_project.dir/main.cpp.i
.PHONY : main.cpp.i

main.s: main.cpp.s

.PHONY : main.s

# target to generate assembly for a file
main.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/cripto_project.dir/build.make CMakeFiles/cripto_project.dir/main.cpp.s
.PHONY : main.cpp.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... cripto_project"
	@echo "... lib/assets/encryptions/database_encryption.o"
	@echo "... lib/assets/encryptions/database_encryption.i"
	@echo "... lib/assets/encryptions/database_encryption.s"
	@echo "... lib/assets/examples/test/test_run.o"
	@echo "... lib/assets/examples/test/test_run.i"
	@echo "... lib/assets/examples/test/test_run.s"
	@echo "... main.o"
	@echo "... main.i"
	@echo "... main.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

