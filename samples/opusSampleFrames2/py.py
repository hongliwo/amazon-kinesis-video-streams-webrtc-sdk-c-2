import os

input_file = "testspeak.opus"
output_prefix = "sample-"

with open(input_file, "rb") as infile:
    data = infile.read()

    frame_start = 0
    frame_index = 1

    while frame_start < len(data):
        frame_size = int.from_bytes(data[frame_start:frame_start+4], byteorder='little')
        print("frame_size:%d" % frame_size)
        output_file = output_prefix + "{:03d}".format(frame_index) + ".opus"
        with open(output_file, "wb") as outfile:
            print("2 frame_size:%d" % frame_size)
            outfile.write(data[frame_start+4:frame_start+frame_size])
        frame_start += frame_size + 4
        frame_index += 1
