import * as vscode from 'vscode';
import * as fs from 'fs';
import path from 'path';

import { decodeCertificate, formatCertificate, prettyPrintExtension } from './decoder';
import { DecodedCert, oidMap } from './types';

class Peek509ContentProvider implements vscode.TextDocumentContentProvider {
  private onDidChangeEmitter = new vscode.EventEmitter<vscode.Uri>();
  public onDidChange = this.onDidChangeEmitter.event;

  private content: Map<string, string> = new Map();

  update(uri: vscode.Uri, content: string) {
    this.content.set(uri.toString(), content);
    this.onDidChangeEmitter.fire(uri);
  }

  provideTextDocumentContent(uri: vscode.Uri): string {
    return this.content.get(uri.toString()) || '';
  }
}

const contentProvider = new Peek509ContentProvider();

export async function activate(context: vscode.ExtensionContext) {
  // Register the content provider once
  vscode.workspace.registerTextDocumentContentProvider('peek509', contentProvider);

  /**
   * Register the decodeCert command.
   * If this command is run via right-click on a file in the file explorer, the file Uri will be passed in.
   * If Uri does not exist, the command was run from the command palette.
   */
  const peek509DecodeCertificate = vscode.commands.registerCommand('peek509.decodeCert', async (uri: vscode.Uri) => {
    if (!uri) {
      // Command palette - open a file dialog to let the user select a file to decode.
      const fileUri = await vscode.window.showOpenDialog({
        canSelectMany: false,
        filters: { 'Certificate Files': ['pem', 'crt'] },
      });
      if (!fileUri || fileUri.length === 0) {
        vscode.window.showInformationMessage(
          'Peek509: To decode a certificate in your workspace, right-click a .pem or .crt file.'
        );
        return;
      }
      uri = fileUri[0];
    }

    try {
      const useWebView = vscode.workspace.getConfiguration('peek509').get('renderMode', 'webview') === 'webview';
      const theme = vscode.workspace.getConfiguration('peek509').get('theme', 'light');

      // Decode the certificate and show either in webview or text document.

      // Attempt to read the file then decode and format the output.  Expects PEM format.
      const content = fs.readFileSync(uri.fsPath, 'utf8');
      // const decodedCert = decodeCertificate(content);
      const decodedCert = await decodeCertificate(content);

      if (!decodedCert) {
        vscode.window.showErrorMessage('Failed to decode the certificate.');
        return;
      }
      const formatted = formatCertificate(decodedCert);
      const decoded = `Decoded content for: ${path.basename(uri.fsPath)}\n\n` + formatted;

      if (useWebView) {
        // Show in webview
        const panel = vscode.window.createWebviewPanel('peek509Webview', 'Peek509 Viewer', vscode.ViewColumn.One, {
          enableScripts: true,
        });

        panel.webview.html = getWebviewContent(decodedCert, theme);
      } else {
        // Create a Virtual Document Provider to display the results.
        vscode.workspace.registerTextDocumentContentProvider('peek509', {
          provideTextDocumentContent(uri: vscode.Uri): string {
            return decoded;
          },
        });

        // Display the results in a virtual document.
        const vUri = vscode.Uri.parse('peek509:' + path.basename(uri.fsPath) + '.decoded.txt');

        // Update the content provider with new content
        contentProvider.update(vUri, decoded);

        // Open or show the document
        const doc = await vscode.workspace.openTextDocument(vUri);
        await vscode.window.showTextDocument(doc, { preview: true });
      }
    } catch (err) {
      vscode.window.showErrorMessage(`Failed to read file: ${err}`);
      return;
    }
  });

  context.subscriptions.push(peek509DecodeCertificate);
}

function getWebviewContent(decodeCert: DecodedCert, theme: string): string {
  const isDark = theme === 'dark';

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Peek509 Certificate Viewer</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --bg-primary: ${isDark ? '#111827' : '#ffffff'};
      --bg-secondary: ${isDark ? '#1f2937' : '#f3f4f6'};
      --text-primary: ${isDark ? '#e5e7eb' : '#1f2937'};
      --text-secondary: ${isDark ? '#9ca3af' : '#6b7280'};
      --border-color: ${isDark ? '#374151' : '#e5e7eb'};
      --accent-color: ${isDark ? '#60a5fa' : '#2563eb'};
      --accent-hover: ${isDark ? '#3b82f6' : '#1d4ed8'};
      --code-bg: ${isDark ? '#374151' : '#e5e7eb'};
    }
    
    body {
      background-color: var(--bg-primary);
      color: var(--text-primary);
    }
    
    h1, h2 { color: var(--accent-color); }
    
    .section-box {
      background-color: var(--bg-secondary);
      border: 1px solid var(--border-color);
    }
    
    summary { cursor: pointer; }
    summary:hover { color: var(--accent-color); }
    
    code, pre {
      background-color: var(--code-bg);
      color: var(--text-primary);
      border: 1px solid var(--border-color);
      word-break: break-all;
      white-space: pre-wrap;
    }
    
    button {
      background-color: var(--accent-color);
      transition: background-color 0.2s;
      color: white;
      border: none;
      padding: 0.5rem 1rem;
      border-radius: 0.375rem;
      cursor: pointer;
      font-size: 0.875rem;
    }
    
    button:hover {
      background-color: var(--accent-hover);
    }

    #themeToggle {
      position: fixed;
      top: 1.5rem;
      right: 1.5rem;
      z-index: 1000;
      padding: 0.5rem;
    }
    
    table td { border-bottom: 1px solid var(--border-color); }
    table tr:last-child td { border-bottom: none; }
  </style>
</head>
<body class="font-sans">
  <button id="themeToggle" title="Toggle dark/light mode">
    <span id="themeIcon">${isDark ? '☀️' : '🌙'}</span>
  </button>

  <div class="max-w-4xl mx-auto p-6">
    <h1 class="text-2xl font-bold mb-4">X.509 Certificate</h1>

    <!-- Subject / Issuer -->
    <section class="mb-6">
      <div class="flex items-start align-top mb-4 space-x-4">
        <div class="flex-1">
          <h2 class="text-lg font-semibold mb-2">Subject</h2>
          <div class="section-box p-4 rounded text-sm">
            <table class="w-full">
              ${decodeCert.subject
                .map(attr => {
                  const label = oidMap[attr.name] ?? `OID ${attr.name}`;
                  return `<tr><td class="pr-2"><strong>${label}:</strong></td><td>${attr.value}</td></tr>`;
                })
                .join('')}  
            </table>
          </div>
        </div>
        <div class="flex-1">
          <h2 class="text-lg font-semibold mb-2">Issuer</h2>
          <div class="section-box p-4 rounded text-sm">
            <table class="w-full">
              ${decodeCert.issuer
                .map(attr => {
                  const label = oidMap[attr.name] ?? `OID ${attr.name}`;
                  return `<tr><td class="pr-2"><strong>${label}:</strong></td><td>${attr.value}</td></tr>`;
                })
                .join('')}  
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- Validity -->
    <section class="mb-6">
      <h2 class="text-lg font-semibold mb-2">Validity</h2>
      <div class="section-box p-4 rounded text-sm">
        <p><strong>Not Before:</strong> ${decodeCert.notBefore}</p>
        <p><strong>Not After:</strong> ${decodeCert.notAfter}</p>
        ${
          decodeCert.notAfter < new Date()
            ? '<p class="text-red-600 font-semibold">This certificate has expired.</p>'
            : ''
        }
      </div>
    </section>

    <!-- Serial Number & Fingerprint -->
    <section class="mb-6">
      <h2 class="text-lg font-semibold mb-2">Identifiers</h2>
      <div class="section-box p-4 rounded text-sm space-y-2">
        <p><strong>Serial Number:</strong> ${decodeCert.serialNumber}</p>
        <p><strong>SHA-256 Fingerprint:</strong> <span id="copyFingerprint" class="cursor-pointer hover:opacity-80 rounded p-1" title="Click to copy fingerprint." style="background-color: var(--code-bg);">${
          decodeCert.fingerprint
        }</span></p>
      </div>
    </section>

    <!-- Public Key -->
    <section class="mb-6">
      <h2 class="text-lg font-semibold mb-2">Public Key</h2>
      <div class="section-box p-4 rounded text-sm">
        ${
          decodeCert.publicKey.rsa
            ? `
            <details>
              <summary class="font-medium mb-3">RSA Details</summary>
              <p><strong>Type:</strong> RSA</p>
              <p class="mt-2"><strong>Modulus:</strong>
              <pre id="copyModulus" class="p-2 rounded mt-2 cursor-pointer hover:opacity-80" title="Click to copy modulus.">${decodeCert.publicKey.rsa.modulus}</pre></p>
              <p class="mt-2"><strong>Exponent:</strong> ${decodeCert.publicKey.rsa.exponent}</p>
            </details>
            `
            : decodeCert.publicKey.ecdsa
            ? `
            <details>
              <summary class="font-medium mb-3">ECDSA Details</summary>
              <p><strong>Type:</strong> ECDSA</p> 
              <p class="mt-2"><strong>Curve OID:</strong> ${decodeCert.publicKey.ecdsa.curveOID}</p> 
              <p class="mt-2"><strong>Curve Name:</strong> ${decodeCert.publicKey.ecdsa.curveName ?? 'Unknown'}</p> 
              <p class="mt-2"><strong>Public Key (Hex):</strong></p>
              <pre id="copyPublicKey" class="p-2 rounded mt-2 cursor-pointer hover:opacity-80" title="Click to copy public key.">${
                decodeCert.publicKey.ecdsa.publicKeyHex
              }</pre>
            </details>
            `
            : `<p>Unknown Public Key Type</p>`
        }
      </div>
    </section>

    <!-- Extensions -->
    <section class="mb-6">
      <h2 class="text-lg font-semibold mb-2">Extensions</h2>
      ${
        decodeCert.extensions
          ?.map(
            ext => `<details class="section-box p-4 rounded text-sm mb-2">
          <summary class="font-medium">${ext.name}${
              ext.critical ? ' <span class="text-red-500">(critical)</span>' : ''
            }</summary>
          <div class="mt-3 pl-4">
            ${prettyPrintExtension(ext, 'html')}
          </div>
        </details>`
          )
          .join('\n') || '<p class="text-gray-500">No extensions found.</p>'
      }
    </section>

    <!-- PEM Content -->
    <section class="mb-6">
      <h2 class="text-lg font-semibold mb-2">PEM Content</h2>
      <pre id="pemContent" 
           class="p-4 rounded text-sm overflow-x-auto w-full cursor-pointer hover:opacity-80" 
           title="Click to copy PEM content.">
${decodeCert.decodedPem?.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}
      </pre>
    </section>
  </div>

  <script>
    let isDark = ${isDark ? 'true' : 'false'};

    function updateTheme() {
      const root = document.documentElement;
      const isDarkMode = isDark;
      
      const colors = {
        dark: {
          bgPrimary: '#111827',
          bgSecondary: '#1f2937',
          textPrimary: '#e5e7eb',
          textSecondary: '#9ca3af',
          borderColor: '#374151',
          accentColor: '#60a5fa',
          accentHover: '#3b82f6',
          codeBg: '#374151',
        },
        light: {
          bgPrimary: '#ffffff',
          bgSecondary: '#f3f4f6',
          textPrimary: '#1f2937',
          textSecondary: '#6b7280',
          borderColor: '#e5e7eb',
          accentColor: '#2563eb',
          accentHover: '#1d4ed8',
          codeBg: '#e5e7eb',
        }
      };

      const theme = isDarkMode ? colors.dark : colors.light;
      root.style.setProperty('--bg-primary', theme.bgPrimary);
      root.style.setProperty('--bg-secondary', theme.bgSecondary);
      root.style.setProperty('--text-primary', theme.textPrimary);
      root.style.setProperty('--text-secondary', theme.textSecondary);
      root.style.setProperty('--border-color', theme.borderColor);
      root.style.setProperty('--accent-color', theme.accentColor);
      root.style.setProperty('--accent-hover', theme.accentHover);
      root.style.setProperty('--code-bg', theme.codeBg);

      document.getElementById('themeIcon').textContent = isDarkMode ? '☀️' : '🌙';
    }

    document.getElementById('themeToggle').addEventListener('click', () => {
      isDark = !isDark;
      updateTheme();
    });

    document.getElementById('copyFingerprint')?.addEventListener('click', () => {
      navigator.clipboard.writeText(\`${decodeCert.fingerprint}\`);
    });

    document.getElementById('copyModulus')?.addEventListener('click', () => {
      navigator.clipboard.writeText(\`${decodeCert.publicKey?.rsa?.modulus}\`);
    });

    document.getElementById('copyPublicKey')?.addEventListener('click', () => {
      navigator.clipboard.writeText(\`${decodeCert.publicKey?.ecdsa?.publicKeyHex}\`);
    });

    document.getElementById('pemContent')?.addEventListener('click', () => {
      navigator.clipboard.writeText(\`${decodeCert.decodedPem}\`);
    });
  </script>
</body>
</html>
  `;
}

export function deactivate() {}
