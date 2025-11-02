import * as vscode from 'vscode';
import * as fs from 'fs';
import path from 'path';

import { decodeCertificate, formatCertificate } from './decoder';

export async function activate(context: vscode.ExtensionContext) {
  /**
   * Register the decodeCert command.
   * If this command is run via right-click on a file in the file explorer, the file Uri will be passed in.
   * If Uri does not exist, the command was run from the command palette.
   */
  const disposable = vscode.commands.registerCommand('peek509.decodeCert', async (uri: vscode.Uri) => {
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

      // Create a Virtual Document Provider to display the results.
      vscode.workspace.registerTextDocumentContentProvider('peek509', {
        provideTextDocumentContent(uri: vscode.Uri): string {
          return decoded;
        },
      });

      // Display the results in a virtual document.
      const vUri = vscode.Uri.parse('peek509:' + path.basename(uri.fsPath) + '.decoded.txt');
      vscode.workspace.openTextDocument(vUri).then(doc => {
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
