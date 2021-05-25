import liblzfse


if __name__ == "__main__":
    data = liblzfse.decompress(open(sys.argv[1], "rb").read())
    if data:
        open(sys.argv[2], "wb").write(data)
