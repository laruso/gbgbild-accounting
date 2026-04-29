"""
Frida hook for SCP7595.dll in the running LFP Accounting Tool.
Hooks EditCmdDataForAnalysis and the internal decrypt function to capture:
  - Input blob (raw ji: data)
  - Key bytes
  - Decrypted output
  - AnalysisJobLog input and output

Run: python frida_hook.py
Then trigger a Refresh in the LFP Accounting Tool.
"""
import frida
import sys
import io
import time
import json

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PROCESS_NAME = "LFPAccountingTool.exe"

# JavaScript to inject — hooks multiple functions
HOOK_SCRIPT = """
// Find the DLL base address
var mod = Process.getModuleByName("SCP7595.dll");
if (!mod) {
    send({type: "error", msg: "SCP7595.dll not found"});
} else {
    send({type: "info", msg: "SCP7595.dll at " + mod.base});

    // ===== Hook EditCmdDataForAnalysis (RVA 0x8b30) =====
    var editCmd = mod.base.add(0x8b30);
    Interceptor.attach(editCmd, {
        onEnter: function(args) {
            this.param1 = args[0];  // input data (raw SNMP response)
            this.param2 = args[1];  // unknown
            this.param3 = args[2];  // key source

            // Dump param1 (input data) - look for "ji:"
            try {
                var p1_data = this.param1.readByteArray(400);
                send({type: "editcmd_enter",
                      param1_hex: bytesToHex(p1_data),
                      param2: this.param2.toString(),
                      param3: this.param3.toString()});

                // Dump param3 (key source) - 20 bytes
                if (this.param3 && !this.param3.isNull()) {
                    var p3_data = this.param3.readByteArray(20);
                    send({type: "editcmd_param3", hex: bytesToHex(p3_data)});
                }
            } catch(e) {
                send({type: "editcmd_error", msg: e.toString()});
            }
        },
        onLeave: function(retval) {
            send({type: "editcmd_leave", retval: retval.toInt32()});
        }
    });

    // ===== Hook the internal decrypt function (RVA 0xd1e0) =====
    var decryptFn = mod.base.add(0xd1e0);
    Interceptor.attach(decryptFn, {
        onEnter: function(args) {
            // thiscall: ecx = source data, edx = output buffer
            // stack args: [0] = length, [1] = key pointer
            this.source = this.context.ecx;
            this.output = this.context.edx;
            this.length = args[0].toInt32();
            this.keyPtr = args[1];

            try {
                // Dump source data (the encrypted blob)
                var src_data = this.source.readByteArray(Math.min(this.length, 208));
                send({type: "decrypt_enter",
                      source_hex: bytesToHex(src_data),
                      length: this.length,
                      output_addr: this.output.toString(),
                      key_addr: this.keyPtr.toString()});

                // Dump the full key data (10 bytes at key pointer)
                if (this.keyPtr && !this.keyPtr.isNull()) {
                    var key_data = this.keyPtr.readByteArray(16);
                    send({type: "decrypt_key", hex: bytesToHex(key_data)});
                }
            } catch(e) {
                send({type: "decrypt_enter_error", msg: e.toString()});
            }
        },
        onLeave: function(retval) {
            // Dump the decrypted output
            try {
                if (this.output && !this.output.isNull() && this.length > 0) {
                    var out_data = this.output.readByteArray(Math.min(this.length, 208));
                    send({type: "decrypt_output", hex: bytesToHex(out_data), length: this.length});
                }
            } catch(e) {
                send({type: "decrypt_output_error", msg: e.toString()});
            }
        }
    });

    // ===== Hook AnalysisJobLog (RVA 0x4800) =====
    var analysisJobLog = mod.base.add(0x4800);
    Interceptor.attach(analysisJobLog, {
        onEnter: function(args) {
            this.param1 = args[0];
            this.param2 = args[1];
            this.param3 = args[2];
            try {
                // param1 is the hex-encoded wide string input
                var p1_str = this.param1.readUtf16String(200);
                send({type: "analysis_enter",
                      param1_preview: p1_str ? p1_str.substring(0, 200) : "null",
                      param2: this.param2.toString(),
                      param3: this.param3.toString()});
            } catch(e) {
                send({type: "analysis_enter_error", msg: e.toString()});
            }
        },
        onLeave: function(retval) {
            send({type: "analysis_leave", retval: retval.toInt32()});
        }
    });

    send({type: "info", msg: "All hooks installed. Trigger a Refresh in the LFP tool."});
}

function bytesToHex(buffer) {
    if (!buffer) return "";
    var hex = "";
    var view = new Uint8Array(buffer);
    for (var i = 0; i < view.length; i++) {
        hex += ("0" + view[i].toString(16)).slice(-2);
    }
    return hex;
}
"""

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type', '?')

        if msg_type == 'info':
            print(f"[INFO] {payload['msg']}")
        elif msg_type == 'error':
            print(f"[ERROR] {payload['msg']}")
        elif msg_type == 'editcmd_enter':
            print(f"\n{'='*60}")
            print(f"[EditCmdDataForAnalysis ENTER]")
            print(f"  param1 (input): {payload['param1_hex'][:80]}...")
            print(f"  param2: {payload['param2']}")
            print(f"  param3: {payload['param3']}")
        elif msg_type == 'editcmd_param3':
            print(f"  param3 data (20 bytes): {payload['hex']}")
        elif msg_type == 'editcmd_leave':
            print(f"[EditCmdDataForAnalysis LEAVE] retval={payload['retval']}")
        elif msg_type == 'decrypt_enter':
            print(f"\n[Decrypt ENTER]")
            print(f"  source ({payload['length']} bytes): {payload['source_hex'][:80]}...")
            print(f"  output addr: {payload['output_addr']}")
            print(f"  key addr: {payload['key_addr']}")
        elif msg_type == 'decrypt_key':
            print(f"  KEY (16 bytes): {payload['hex']}")
            # Parse the key
            key_hex = payload['hex']
            key_bytes = bytes.fromhex(key_hex)
            print(f"  KEY bytes: {list(key_bytes[:10])}")
        elif msg_type == 'decrypt_output':
            hex_out = payload['hex']
            print(f"[Decrypt OUTPUT] ({payload['length']} bytes)")
            print(f"  decrypted: {hex_out[:120]}...")
            # Try to parse as TLV
            data_bytes = bytes.fromhex(hex_out)
            # Show as lines of 16 bytes
            for i in range(0, min(len(data_bytes), 64), 16):
                chunk = data_bytes[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"  {i:3d}: {hex_str:<48s} {ascii_str}")
        elif msg_type == 'analysis_enter':
            print(f"\n[AnalysisJobLog ENTER]")
            print(f"  param1 (hex string): {payload['param1_preview'][:120]}...")
            print(f"  param2: {payload['param2']}")
            print(f"  param3: {payload['param3']}")
        elif msg_type == 'analysis_leave':
            print(f"[AnalysisJobLog LEAVE] retval={payload['retval']}")
        elif 'error' in msg_type:
            print(f"[{msg_type}] {payload.get('msg', payload)}")
        else:
            print(f"[{msg_type}] {payload}")
    elif message['type'] == 'error':
        print(f"[FRIDA ERROR] {message}")

def main():
    print(f"Attaching to {PROCESS_NAME}...")
    try:
        session = frida.attach(PROCESS_NAME)
    except frida.ProcessNotFoundError:
        print(f"Process {PROCESS_NAME} not found!")
        sys.exit(1)

    print("Injecting hooks...")
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()

    print("\nHooks active. Now trigger a Refresh in the LFP Accounting Tool.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDetaching...")
        session.detach()
        print("Done.")

if __name__ == "__main__":
    main()
