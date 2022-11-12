package GUI;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

public class Frm extends javax.swing.JFrame {

    public Frm() {
        initComponents();
        setTitle("Nhom 12 _ Nhap mon An toan thong tin");
        setLocationRelativeTo(null);
        cbLoaiMaHoa.setSelectedIndex(0);
    }

    public String encryptHoanVi(String plainText, int depth) throws Exception {
        int r = depth, len = plainText.length();
        int c = len / depth;
        char mat[][] = new char[r][c];
        int k = 0;

        String cipherText = "";

        for (int i = 0; i < c; i++) {
            for (int j = 0; j < r; j++) {
                if (k != len) {
                    mat[j][i] = plainText.charAt(k++);
                } else {
                    mat[j][i] = 'X';
                }
            }
        }
        for (int i = 0; i < r; i++) {
            for (int j = 0; j < c; j++) {
                cipherText += mat[i][j];
            }
        }
        return cipherText;
    }

    public String decryptHoanVi(String cipherText, int depth) throws Exception {
        int r = depth, len = cipherText.length();
        int c = len / depth;
        char mat[][] = new char[r][c];
        int k = 0;

        String plainText = "";

        for (int i = 0; i < r; i++) {
            for (int j = 0; j < c; j++) {
                mat[i][j] = cipherText.charAt(k++);
            }
        }
        for (int i = 0; i < c; i++) {
            for (int j = 0; j < r; j++) {
                plainText += mat[j][i];
            }
        }

        return plainText;
    }

    public String encryptAES(String strToEncrypt, String myKey, int optionAES) {
        try {

            String loaiMaHoaAES;
            switch (optionAES) {
                case 0:
                    loaiMaHoaAES = "AES/ECB/PKCS5Padding";
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    byte[] key = myKey.getBytes("UTF-8");
                    key = sha.digest(key);
                    key = Arrays.copyOf(key, 16);
                    SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                    Cipher cipher = Cipher.getInstance(loaiMaHoaAES);
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));

                case 1:
                    loaiMaHoaAES = "AES/CBC/PKCS5Padding";
                    String keyCBC = myKey;
                    String initVector = "encryptionIntVec";
                    IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
                    SecretKeySpec skeySpec = new SecretKeySpec(keyCBC.getBytes("UTF-8"), "AES");
                    Cipher cipherCBC = Cipher.getInstance(loaiMaHoaAES);
                    cipherCBC.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
                    byte[] encrypted = cipherCBC.doFinal(strToEncrypt.getBytes("UTF-8"));
                    return Base64.getEncoder().encodeToString(cipherCBC.doFinal(strToEncrypt.getBytes("UTF-8")));

                case 2:
                    loaiMaHoaAES = "AES/CFB8/NoPadding";
                case 3:
                    loaiMaHoaAES = "AES/OFB32/PKCS5Padding";
            }

        } catch (Exception e) {
            System.out.println(e.toString());
        }
        return null;
    }

    public String decryptAES(String strToDecrypt, String myKey, int optionAES) {
        try {
            String loaiMaHoaAES = "";
            switch (optionAES) {
                case 0:
                    loaiMaHoaAES = "AES/ECB/PKCS5Padding";
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    byte[] key = myKey.getBytes("UTF-8");
                    key = sha.digest(key);
                    key = Arrays.copyOf(key, 16);
                    SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                    Cipher cipher = Cipher.getInstance(loaiMaHoaAES);
                    cipher.init(Cipher.DECRYPT_MODE, secretKey);
                    return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));

                case 1:
                    loaiMaHoaAES = "AES/CBC/PKCS5Padding";
                    String keyCBC = myKey;
                    String initVector = "encryptionIntVec";
                    IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
                    SecretKeySpec skeySpec = new SecretKeySpec(keyCBC.getBytes("UTF-8"), "AES");
                    Cipher cipherCBC = Cipher.getInstance(loaiMaHoaAES);
                    cipherCBC.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                    return new String(cipherCBC.doFinal(Base64.getDecoder().decode(strToDecrypt)));

                case 2:
                    loaiMaHoaAES = "AES/CFB8/NoPadding";
                    break;
                case 3:
                    loaiMaHoaAES = "AES/OFB32/PKCS5Padding";
                    break;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jPanel2 = new javax.swing.JPanel();
        lblBanRo = new javax.swing.JLabel();
        txtBanRo = new javax.swing.JTextField();
        jPanel3 = new javax.swing.JPanel();
        lblKey = new javax.swing.JLabel();
        txtKey = new javax.swing.JTextField();
        jPanel4 = new javax.swing.JPanel();
        lblBanMa = new javax.swing.JLabel();
        txtBanMa = new javax.swing.JTextField();
        jPanel5 = new javax.swing.JPanel();
        btnMaHoa = new javax.swing.JButton();
        btnGiaiMa = new javax.swing.JButton();
        lblLoaiMaHoa = new javax.swing.JLabel();
        cbLoaiMaHoa = new javax.swing.JComboBox<>();
        cbLoaiAES = new javax.swing.JComboBox<>();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jPanel1.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        lblBanRo.setFont(new java.awt.Font("Times New Roman", 0, 36)); // NOI18N
        lblBanRo.setLabelFor(txtBanRo);
        lblBanRo.setText("Bản rõ: ");

        txtBanRo.setFont(new java.awt.Font("Times New Roman", 0, 24)); // NOI18N
        txtBanRo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtBanRoActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(131, 131, 131)
                .addComponent(lblBanRo)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(txtBanRo, javax.swing.GroupLayout.PREFERRED_SIZE, 723, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(16, 16, 16)
                        .addComponent(txtBanRo, javax.swing.GroupLayout.PREFERRED_SIZE, 67, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(30, 30, 30)
                        .addComponent(lblBanRo)))
                .addContainerGap(37, Short.MAX_VALUE))
        );

        lblKey.setFont(new java.awt.Font("Times New Roman", 0, 36)); // NOI18N
        lblKey.setLabelFor(txtKey);
        lblKey.setText("Key: ");

        txtKey.setFont(new java.awt.Font("Times New Roman", 0, 24)); // NOI18N
        txtKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtKeyActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(170, 170, 170)
                .addComponent(lblKey)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(txtKey, javax.swing.GroupLayout.PREFERRED_SIZE, 724, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(54, Short.MAX_VALUE))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(16, 16, 16)
                        .addComponent(txtKey, javax.swing.GroupLayout.PREFERRED_SIZE, 67, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(29, 29, 29)
                        .addComponent(lblKey)))
                .addContainerGap(36, Short.MAX_VALUE))
        );

        lblBanMa.setFont(new java.awt.Font("Times New Roman", 0, 36)); // NOI18N
        lblBanMa.setLabelFor(txtBanMa);
        lblBanMa.setText("Bản mã: ");

        txtBanMa.setFont(new java.awt.Font("Times New Roman", 0, 24)); // NOI18N
        txtBanMa.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtBanMaActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(lblBanMa)
                .addGap(18, 18, 18)
                .addComponent(txtBanMa, javax.swing.GroupLayout.PREFERRED_SIZE, 724, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(51, 51, 51))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(18, 18, 18)
                        .addComponent(txtBanMa, javax.swing.GroupLayout.PREFERRED_SIZE, 67, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(31, 31, 31)
                        .addComponent(lblBanMa)))
                .addContainerGap(23, Short.MAX_VALUE))
        );

        btnMaHoa.setFont(new java.awt.Font("Times New Roman", 0, 24)); // NOI18N
        btnMaHoa.setText("Mã hóa");
        btnMaHoa.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnMaHoaActionPerformed(evt);
            }
        });

        btnGiaiMa.setFont(new java.awt.Font("Times New Roman", 0, 24)); // NOI18N
        btnGiaiMa.setText("Giải mã");
        btnGiaiMa.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGiaiMaActionPerformed(evt);
            }
        });

        lblLoaiMaHoa.setFont(new java.awt.Font("Times New Roman", 0, 36)); // NOI18N
        lblLoaiMaHoa.setLabelFor(cbLoaiMaHoa);
        lblLoaiMaHoa.setText("Loại mã hóa: ");

        cbLoaiMaHoa.setFont(new java.awt.Font("Times New Roman", 0, 24)); // NOI18N
        cbLoaiMaHoa.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Mã hóa hoán vị", "AES" }));

        cbLoaiAES.setFont(new java.awt.Font("Times New Roman", 0, 18)); // NOI18N
        cbLoaiAES.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "EBC", "CBC" }));
        cbLoaiAES.setPreferredSize(new java.awt.Dimension(70, 35));

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel5Layout.createSequentialGroup()
                .addGap(51, 51, 51)
                .addComponent(lblLoaiMaHoa)
                .addGap(66, 66, 66)
                .addComponent(cbLoaiMaHoa, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(cbLoaiAES, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(btnMaHoa)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(btnGiaiMa)
                .addGap(103, 103, 103))
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel5Layout.createSequentialGroup()
                .addContainerGap(40, Short.MAX_VALUE)
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnMaHoa)
                    .addComponent(btnGiaiMa)
                    .addComponent(lblLoaiMaHoa)
                    .addComponent(cbLoaiMaHoa, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(cbLoaiAES, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(37, 37, 37))
        );

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void txtBanRoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtBanRoActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtBanRoActionPerformed

    private void txtKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtKeyActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtKeyActionPerformed

    private void txtBanMaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtBanMaActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtBanMaActionPerformed

    private void btnGiaiMaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnGiaiMaActionPerformed
        // TODO add your handling code here:
        String banMa = txtBanMa.getText();
        String key = txtKey.getText();
        int chooseMaHoa = cbLoaiMaHoa.getSelectedIndex();

        switch (chooseMaHoa) {
            case 0:
                // Giai ma hoan vi
                Pattern pattern = Pattern.compile("\\d*");
                Matcher matcher = pattern.matcher(txtKey.getText().toString());
                if (matcher.matches()) {
                    try {
                        if (chooseMaHoa == 0) {
                            txtBanRo.setText(decryptHoanVi(banMa, Integer.parseInt(key)));
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "Key phải là số!");
                }
                break;

            case 1:
                // Giai ma AES
                if (txtKey.getText().length() == 16) {
                    try {
                        if (chooseMaHoa == 1) {
                            txtBanRo.setText(decryptAES(banMa, key, cbLoaiAES.getSelectedIndex()));
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "Độ dài key phải là 16!");
                }
                break;
            default:
                throw new AssertionError();
        }
    }//GEN-LAST:event_btnGiaiMaActionPerformed

    private void btnMaHoaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnMaHoaActionPerformed
        // TODO add your handling code here:
        String banRo = txtBanRo.getText();
        String key = txtKey.getText();
        int chooseMaHoa = cbLoaiMaHoa.getSelectedIndex();

        switch (chooseMaHoa) {
            case 0:
                // Giai ma hoan vi
                Pattern pattern = Pattern.compile("\\d*");
                Matcher matcher = pattern.matcher(txtKey.getText().toString());
                if (matcher.matches()) {
                    try {
                        if (chooseMaHoa == 0) {
                            txtBanMa.setText(encryptHoanVi(banRo, Integer.parseInt(key)));
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "Key phải là số!");
                }
                break;

            case 1:
                // Giai ma AES
                if (txtKey.getText().length() == 16) {
                    try {
                        if (chooseMaHoa == 1) {
                            txtBanMa.setText(encryptAES(banRo, key, cbLoaiAES.getSelectedIndex()));
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "Độ dài key phải là 16!");
                }
                break;
            default:
                throw new AssertionError();
        }
    }//GEN-LAST:event_btnMaHoaActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;

                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Frm.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);

        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Frm.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);

        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Frm.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);

        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Frm.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Frm().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnGiaiMa;
    private javax.swing.JButton btnMaHoa;
    private javax.swing.JComboBox<String> cbLoaiAES;
    private javax.swing.JComboBox<String> cbLoaiMaHoa;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JLabel lblBanMa;
    private javax.swing.JLabel lblBanRo;
    private javax.swing.JLabel lblKey;
    private javax.swing.JLabel lblLoaiMaHoa;
    private javax.swing.JTextField txtBanMa;
    private javax.swing.JTextField txtBanRo;
    private javax.swing.JTextField txtKey;
    // End of variables declaration//GEN-END:variables
}
