FROM alpine:3.18
RUN apk add --no-cache git

RUN git config --global user.email "test@example.com" && \
    git config --global user.name "Test User" && \
    git config --global init.defaultBranch main

RUN git init /repo && cd /repo && \
    echo '{"name":"test-app","dependencies":{"lodash":"4.17.11","express":"4.17.1"}}' > package.json && \
    echo 'requests==2.18.0\nurllib3==1.21.1' > requirements.txt && \
    git add . && git commit -m "Initial commit"

RUN cd /repo && \
    printf 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDB_PASSWORD=supersecret123\n' > .env && \
    printf "def connect():\n    password = 'admin123'\n    return password\n" > auth.py && \
    git add . && git commit -m "Add config and auth module"

RUN cd /repo && \
    echo '# Test App' > README.md && \
    git add . && git commit -m "Add README"

CMD ["tail", "-f", "/dev/null"]
