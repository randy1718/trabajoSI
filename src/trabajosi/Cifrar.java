/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trabajosi;

import static com.sun.org.apache.xalan.internal.xsltc.compiler.util.Type.String;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFileChooser;

/**
 *
 * @author larti
 */
public class Cifrar extends javax.swing.JFrame {

    
    private final FileShare rsa;
    /**
     * Creates new form NewJFrame
     */
    public Cifrar() {
        initComponents();
         this.setLocationRelativeTo(null); 
          rsa = new FileShare();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jTabbedPane1 = new javax.swing.JTabbedPane();
        jCheckBoxMenuItem1 = new javax.swing.JCheckBoxMenuItem();
        jFileChooser1 = new javax.swing.JFileChooser();
        jPanel1 = new javax.swing.JPanel();
        jInternalFrame1 = new javax.swing.JInternalFrame();
        dir_clave = new javax.swing.JTextField();
        jButton3 = new javax.swing.JButton();
        Cifrar = new javax.swing.JButton();
        dir_archivo = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        archivo = new javax.swing.JButton();
        clave = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();

        jCheckBoxMenuItem1.setSelected(true);
        jCheckBoxMenuItem1.setText("jCheckBoxMenuItem1");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 100, Short.MAX_VALUE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 100, Short.MAX_VALUE)
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jInternalFrame1.setBackground(new java.awt.Color(153, 255, 255));
        jInternalFrame1.setForeground(new java.awt.Color(0, 0, 0));
        jInternalFrame1.setVisible(true);

        dir_clave.setEditable(false);
        dir_clave.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dir_claveActionPerformed(evt);
            }
        });

        jButton3.setBackground(new java.awt.Color(255, 153, 102));
        jButton3.setForeground(new java.awt.Color(0, 0, 0));
        jButton3.setText("Volver");
        jButton3.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jButton3MouseClicked(evt);
            }
        });

        Cifrar.setBackground(new java.awt.Color(255, 153, 102));
        Cifrar.setForeground(new java.awt.Color(0, 0, 0));
        Cifrar.setText("Cifrar");
        Cifrar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CifrarActionPerformed(evt);
            }
        });

        dir_archivo.setEditable(false);
        dir_archivo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dir_archivoActionPerformed(evt);
            }
        });

        jLabel2.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(0, 0, 0));
        jLabel2.setText("Archivo");

        jLabel3.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(0, 0, 0));
        jLabel3.setText("Clave publica");

        archivo.setBackground(new java.awt.Color(255, 153, 102));
        archivo.setForeground(new java.awt.Color(0, 0, 0));
        archivo.setText("Seleccionar");
        archivo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                archivoActionPerformed(evt);
            }
        });

        clave.setBackground(new java.awt.Color(255, 153, 102));
        clave.setForeground(new java.awt.Color(0, 0, 0));
        clave.setText("Seleccionar");
        clave.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                claveActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Tw Cen MT", 1, 70)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(0, 0, 0));
        jLabel1.setText("Cifrador");

        javax.swing.GroupLayout jInternalFrame1Layout = new javax.swing.GroupLayout(jInternalFrame1.getContentPane());
        jInternalFrame1.getContentPane().setLayout(jInternalFrame1Layout);
        jInternalFrame1Layout.setHorizontalGroup(
            jInternalFrame1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jInternalFrame1Layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jButton3, javax.swing.GroupLayout.PREFERRED_SIZE, 266, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
            .addGroup(jInternalFrame1Layout.createSequentialGroup()
                .addContainerGap(73, Short.MAX_VALUE)
                .addGroup(jInternalFrame1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel3, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 142, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 79, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(33, 33, 33)
                .addGroup(jInternalFrame1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jInternalFrame1Layout.createSequentialGroup()
                        .addComponent(Cifrar, javax.swing.GroupLayout.PREFERRED_SIZE, 381, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(jInternalFrame1Layout.createSequentialGroup()
                        .addGroup(jInternalFrame1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(dir_archivo, javax.swing.GroupLayout.PREFERRED_SIZE, 381, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(dir_clave, javax.swing.GroupLayout.PREFERRED_SIZE, 381, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 48, Short.MAX_VALUE)
                        .addGroup(jInternalFrame1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(archivo, javax.swing.GroupLayout.PREFERRED_SIZE, 152, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(clave, javax.swing.GroupLayout.PREFERRED_SIZE, 152, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(76, 76, 76))))
            .addGroup(jInternalFrame1Layout.createSequentialGroup()
                .addGap(327, 327, 327)
                .addComponent(jLabel1)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jInternalFrame1Layout.setVerticalGroup(
            jInternalFrame1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jInternalFrame1Layout.createSequentialGroup()
                .addGap(33, 33, 33)
                .addComponent(jLabel1)
                .addGap(86, 86, 86)
                .addGroup(jInternalFrame1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(dir_clave, javax.swing.GroupLayout.PREFERRED_SIZE, 42, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 43, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(clave, javax.swing.GroupLayout.PREFERRED_SIZE, 42, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jInternalFrame1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(dir_archivo, javax.swing.GroupLayout.PREFERRED_SIZE, 42, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 43, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(archivo, javax.swing.GroupLayout.PREFERRED_SIZE, 42, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(31, 31, 31)
                .addComponent(Cifrar, javax.swing.GroupLayout.PREFERRED_SIZE, 42, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 66, Short.MAX_VALUE)
                .addComponent(jButton3, javax.swing.GroupLayout.PREFERRED_SIZE, 42, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jInternalFrame1)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jInternalFrame1)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void CifrarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CifrarActionPerformed
        // TODO add your handling code here:

        String key=dir_clave.getText();
        String file=dir_archivo.getText();
        
        JFileChooser ruta=new JFileChooser();
        ruta.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        ruta.showSaveDialog(this);
        String ubicacion=ruta.getSelectedFile().toString();
        String directory=ubicacion+"\\Cifrado.txt";
        
        try {
            rsa.openFromDiskPublicKey(key);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(Cifrar.class.getName()).log(Level.SEVERE, null, ex);
        }
        String secure;
        try {
            secure = rsa.cifrarArchivo(file);
            System.out.println(secure);
            
            rsa.saveCipherText(secure,directory);
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | UnsupportedEncodingException | NoSuchProviderException ex) {
            Logger.getLogger(Cifrar.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Cifrar.class.getName()).log(Level.SEVERE, null, ex);
        }

        System.out.println(key);
    }//GEN-LAST:event_CifrarActionPerformed

    private void jButton3MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton3MouseClicked
        // TODO add your handling code here:
        this.setVisible(false);
        Inicio i;
        i=new Inicio();
        i.setVisible(true);
    }//GEN-LAST:event_jButton3MouseClicked

    private void dir_archivoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dir_archivoActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dir_archivoActionPerformed

    private void archivoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_archivoActionPerformed
        // TODO add your handling code here:
        JFileChooser f=new JFileChooser();
        f.showOpenDialog(this);
        String ubicacion=f.getSelectedFile().toString();
        dir_archivo.setText(ubicacion);
    }//GEN-LAST:event_archivoActionPerformed

    private void claveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_claveActionPerformed
        // TODO add your handling code here:
        JFileChooser ruta=new JFileChooser();
        ruta.showOpenDialog(this);
        String ubicacion=ruta.getSelectedFile().toString();
        dir_clave.setText(ubicacion);
    }//GEN-LAST:event_claveActionPerformed

    private void dir_claveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dir_claveActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dir_claveActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton Cifrar;
    private javax.swing.JButton archivo;
    private javax.swing.JButton clave;
    private javax.swing.JTextField dir_archivo;
    private javax.swing.JTextField dir_clave;
    private javax.swing.JButton jButton3;
    private javax.swing.JCheckBoxMenuItem jCheckBoxMenuItem1;
    private javax.swing.JFileChooser jFileChooser1;
    private javax.swing.JInternalFrame jInternalFrame1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JTabbedPane jTabbedPane1;
    // End of variables declaration//GEN-END:variables
}
