# Request corpora

Raw HTTP/1.1 requests for the parser and framing tests (`tests/unit/test_h1_parser.c`,
`test_h1_framing.c`) and as seeds. A file is `<expect>-<name>.req`: `<expect>` is `ok` when the
head must parse, or the status the request must be refused with.

The text is stored with LF line ends and read with every LF turned into CRLF, so the files are
readable. Anything else is an escape: `\r` a bare CR, `\n` a bare LF, `\0` a NUL, `\xHH` a byte,
`\\` a backslash.

- `h1/`: parser outcomes (request line, target forms, versions, header syntax).
- `smuggling/`: request smuggling and desync inputs, each refused by the framing rules.
  `<expect>` there is the status of `bst_h1_message_framing` or the request semantics.
