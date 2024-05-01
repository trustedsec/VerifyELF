
all: setup
	gcc -I ./include/ ./src/parseELF_validate_sections.c -o ./bins/parseELF_validate_sections.out -lm
	gcc -I ./include/ ./src/memloader_verifygot.c -o ./bins/memloader_test.out -ldl

debug: setup
	gcc -g -DDEBUG -I ./include/ ./src/parseELF_validate_sections.c -o ./bins/parseELF_validate_sections.out -lm
	gcc -g -DDEBUG -I ./include/ ./src/memloader_verifygot.c -o ./bins/memloader_test.out -ldl

setup:
	mkdir -p ./bins/

clean:
	rm -f ./bins/*.o
	rm -f ./bins/*.out
