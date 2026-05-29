from pathlib import Path
import os
import random


class FirmwareTestMutator:
    """
    Generates SAFE OFFLINE mutated copies for sandbox detector testing.
    Do NOT flash these images.
    """

    def __init__(self, input_file: str):
        self.input_path = Path(input_file)
        self.blob = bytearray(self.input_path.read_bytes())

    def save(self, out_name: str, blob: bytearray):
        Path(out_name).write_bytes(blob)
        print(f"[+] Created test variant: {out_name}")

    def zero_fill_region(self, start: int, length: int, out_name: str):
        test = bytearray(self.blob)
        test[start:start + length] = b"\x00" * length
        self.save(out_name, test)

    def ff_fill_region(self, start: int, length: int, out_name: str):
        test = bytearray(self.blob)
        test[start:start + length] = b"\xFF" * length
        self.save(out_name, test)

    def fragmented_changes(self, count: int, step: int, out_name: str):
        test = bytearray(self.blob)
        base = 0x1000

        for i in range(count):
            off = base + i * step
            if off < len(test):
                test[off] ^= 0xAA

        self.save(out_name, test)

    def entropy_spike_region(self, start: int, length: int, out_name: str):
        test = bytearray(self.blob)
        random_blob = os.urandom(length)
        test[start:start + length] = random_blob
        self.save(out_name, test)

    def vector_table_tamper(self, out_name: str):
        test = bytearray(self.blob)

        # corrupt reset handler only for detector validation
        if len(test) >= 8:
            test[4:8] = (0x12345678).to_bytes(4, "little")

        self.save(out_name, test)


if __name__ == "__main__":
    fw = FirmwareTestMutator("D:/antiforensics/FC001_original_flash_20260401.bin")

    fw.zero_fill_region(0x7000, 512, "test_zero_fill.bin")
    fw.ff_fill_region(0x9000, 512, "test_ff_fill.bin")
    fw.fragmented_changes(25, 257, "test_fragmented.bin")
    fw.entropy_spike_region(0xB000, 2048, "test_entropy_spike.bin")
    fw.vector_table_tamper("test_vector_tamper.bin")