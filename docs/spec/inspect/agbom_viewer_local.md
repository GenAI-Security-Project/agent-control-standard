# Inspect Local BOMs

Run the AgBOM Viewer from your ACS checkout to inspect your own bills of materials (BOMs). The server reads files in place and listens on the loopback address.

1. Install Node.js 22 or later.
2. Create `inventory/` at the root of the ACS checkout and put your BOMs there. Git ignores this folder and its contents. Use subfolders for captures with identical filenames.
3. Open the ACS checkout in VS Code. In the integrated terminal at the repository root, run:

    ```sh
    node tools/agbom-viewer/serve.mjs
    ```

4. Open `http://127.0.0.1:4173/` in your browser. Select **Local BOMs**, then **Refresh local inventory** after adding or changing files.
5. Press **Ctrl+C** in the terminal to stop the server.

Put an ACS snapshot such as `startup.acs.json` and its CycloneDX 2.0-dev export `startup.cdx.json` in the same folder to inspect them together. The viewer also opens standalone CycloneDX 2.0 draft AgBOMs and model AIBOMs such as CycloneDX 1.7. With two or more ACS captures, choose a **Baseline** and **Comparison** to see the changes.

The [public viewer](agbom-viewer/index.html) uses only the bundled examples.
