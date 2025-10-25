import * as vscode from 'vscode';
import * as fs from 'fs';
import { decodeCertificate, formatCertificate } from './decoder';

export function activate(context: vscode.ExtensionContext) {
  const disposable = vscode.commands.registerCommand('peek509.decodeCert', async (uri: vscode.Uri) => {
    try {
      const content = fs.readFileSync(uri.fsPath, 'utf8');
      const decodedCert = decodeCertificate(content);
      if (!decodedCert) {
        vscode.window.showErrorMessage('Failed to decode the certificate.');
        return;
      }
      const formatted = formatCertificate(decodedCert);
      const decoded = 'Decoded content:\n\n' + formatted;

      const doc = await vscode.workspace.openTextDocument({
        content: decoded,
        language: 'plaintext',
      });

      await vscode.window.showTextDocument(doc, { preview: false });
    } catch (err) {
      vscode.window.showErrorMessage(`Failed to read file: ${err}`);
      return;
    }
  });

  context.subscriptions.push(disposable);
}

export function deactivate() {}
