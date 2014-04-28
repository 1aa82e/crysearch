
call "%VS90COMNTOOLS%vsvars32.bat" >NUL:

@pushd c
@call msvc.bat
@popd
@pushd cpp
@call msvc.bat
@popd
