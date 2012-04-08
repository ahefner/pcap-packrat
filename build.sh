#!/bin/sh

sbcl --noinform --no-userinit \
     --disable-debugger \
     --eval "(require :asdf)" \
     --eval "(load \"packrat.asd\")" \
     --eval "(asdf:oos 'asdf:load-op :packrat)" \
     --eval "(packrat::dump-executable)"
