" CVE checker project style info
"
" We use tabs, and use stop of 4 characters
set tabstop=4
set noexpandtab
" Allow >> and << to support the same indentation
set shiftwidth=4

" use C code style
augroup project
	autocmd!
	autocmd BufRead,BufNewFile *.h,*.c set filetype=c.doxygen
augroup END
