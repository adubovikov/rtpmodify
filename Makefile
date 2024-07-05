NAME?=rtpmodify

all:
	go build -o $(NAME) *.go

static:
	CGO_ENABLED=1 GOOS=linux CGO_LDFLAGS="-lm -ldl" go build -a -ldflags '-s -w -extldflags "-static"' -tags netgo -installsuffix netgo -o $(NAME)

debug:
	go build -o $(NAME) *.go


.PHONY: clean
clean:
	rm -fr $(NAME)