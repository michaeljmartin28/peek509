import * as vscode from 'vscode';
import * as fs from 'fs';
import { decodeCertificate, formatCertificate } from './decoder';
import path from 'path';

export function activate(context: vscode.ExtensionContext) {
  const disposable = vscode.commands.registerCommand('peek509.decodeCert', async (uri: vscode.Uri) => {
    if (!uri) {
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
      const content = fs.readFileSync(uri.fsPath, 'utf8');
      const decodedCert = decodeCertificate(content);
      if (!decodedCert) {
        vscode.window.showErrorMessage('Failed to decode the certificate.');
        return;
      }
      const formatted = formatCertificate(decodedCert);
      const decoded = `Decoded content for: ${path.basename(uri.fsPath)}\n\n` + formatted;

      vscode.workspace.registerTextDocumentContentProvider('peek509', {
        provideTextDocumentContent(uri: vscode.Uri): string {
          return decoded;
        },
      });

      const vuri = vscode.Uri.parse('peek509:' + path.basename(uri.fsPath) + '.decoded.txt');
      vscode.workspace.openTextDocument(vuri).then(doc => {
        vscode.window.showTextDocument(doc, { preview: true });
      });
    } catch (err) {
      vscode.window.showErrorMessage(`Failed to read file: ${err}`);
      return;
    }
  });

  context.subscriptions.push(disposable);
}

export function deactivate() {}
