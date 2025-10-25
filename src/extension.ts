import * as vscode from 'vscode';
import * as fs from 'fs';

export function activate(context: vscode.ExtensionContext) {
  console.log('Congratulations, your extension "peek509" is now active!');

  const disposable = vscode.commands.registerCommand('peek509.decodeCert', async (uri: vscode.Uri) => {
    try {
      const content = fs.readFileSync(uri.fsPath, 'utf8');

      // TODO: decode the x509 cert later
      const decoded = 'Decoded content:\n\n' + content;

      const doc = await vscode.workspace.openTextDocument({
        content: decoded,
        language: 'plaintext',
      });

      await vscode.window.showTextDocument(doc, { preview: false });
    } catch (err) {
      vscode.window.showErrorMessage(`Failed to read file: ${err}`);
      return;
    }
    //vscode.window.showInformationMessage('Hello World from peek509!');
  });

  context.subscriptions.push(disposable);
}

// This method is called when your extension is deactivated
export function deactivate() {}
