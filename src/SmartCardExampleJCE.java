

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import javax.security.auth.login.LoginException;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class SmartCardExampleJCE {

	 public static byte[] SelectAPDU_1 = new byte[]{(byte) 0x80,
		        (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02,
		        (byte) 0x3F, (byte) 0x00};
		    	    
	 public static byte[] SelectAPDU_2 = new byte[]{(byte) 0x80,
	            (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02,
	            (byte) 0x09, (byte) 0x00};
		        
	 public static byte[] SelectAPDU_3 = new byte[]{(byte) 0x80,
	            (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02,
	            (byte) 0x09, (byte) 0x03};
	 
	 public static byte[] ReadProfileAPDU = new byte[]{(byte) 0x80, 
	    		(byte) 0xB0, (byte) 0x00, (byte) 0x00,(byte) 0x10};
		      
	
	
	/** ���z�LHICOSPKCS11�hŪ�����ҩM���o�p�_����
	 * @param args
	 * @throws IOException 
	 * @throws CardException 
	 */
	public static void main(String[] args) throws IOException, CardException {
				
	    // show the list of available terminals
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list(); // �[�JException �ʧ@
        System.out.println("terminals_slot(�s���ǦC)" + terminals.size());
        for(int solt =0 ; solt<=terminals.size()-1; solt++){
        	
        System.out.println("Terminals: " + terminals.get(solt).getName());
        // get the first terminal
        CardTerminal terminal = terminals.get(solt);
        // establish a connection with the card
        System.out.println("isCardPresent: " + terminal.isCardPresent());
        	if(terminal.isCardPresent()){
        		//�����X�d�����d���X�� 
        		Card card = terminal.connect("T=1");  
		        //System.out.println("card: " + card);
		        //System.out.println("card: " + card.getATR());
		        
		        CardChannel channel = card.getBasicChannel();
		        //APDU Command
                CommandAPDU command = new CommandAPDU(SelectAPDU_1);
                //APDU Response
                ResponseAPDU response = channel.transmit(command);
                              
                //APDU Command
                CommandAPDU command1 = new CommandAPDU(SelectAPDU_2);
                //APDU Response
                ResponseAPDU response1 = channel.transmit(command1);
                
                //APDU Command
                CommandAPDU command2 = new CommandAPDU(SelectAPDU_3);
                //APDU Response
                ResponseAPDU response2 = channel.transmit(command2);
                
                //APDU Command
                command = new CommandAPDU(ReadProfileAPDU);
                //APDU Response
                response = channel.transmit(command);
                //Display Data
                System.out.println("�d�����d��:"+ new String(Arrays.copyOfRange(response.getData(), 0, 16)));// �d��
		        
		        card.disconnect(false);
		        
		   //   
		        /**
		         * 
		         * �ظmpkcs11�����]�w��
		         * �аѦ�https://docs.oracle.com/javase/8/docs/technotes/guides/security/p11guide.html ����PKCS11�]�w�о\Ū���D2.2
		         * 
		         * pkcs11config �ѼƩw�q����
		         * name ���满���ɮצW��
		         * library �����OPKCS#11�ɮש�m�a����| 
		         * description �y�zpkcs11�ɦW
		         * slot ���wŪ�d��(�u�n��ܨ䤤�@�ӰѼƧY�i)�A�p�G�S�����w�w�]�N�O slot=0
		         * slotListIndex  ���wŪ�d�� (�u�n��ܨ䤤�@�ӰѼƧY�i)�A�p�G�S�����w�w�]�N�O slot=0
		         */
				String pkcs11config =
						   "name=CHTSmartCard\r\n" +
						   "library=" +  System.getenv("WINDIR") + "\\system32\\HiCOSPKCS11.dll\n" +
						   "slotListIndex="+solt ;
				
						   //"library=" + System.getProperty("user.dir") + "\\nativelib\\HiCOSPKCS11v32.dll";
				
				System.out.println("�]�w���:"+pkcs11config);  
				
				//���wPKCS11���ʺA�ɮ׼t�� 		   
				Provider pkcs11Provider =   new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(pkcs11config.getBytes()));
			
				//���o�ϥΪ��귽�W��
				String pkcs11ProviderName = pkcs11Provider.getName();
				System.out.println("�ϥΪ��귽�W��:"+pkcs11ProviderName);
				System.out.println("�ϥΪ�JAVA����:"+pkcs11Provider.getVersion());
				System.out.println("�y�z��DLL�ɮ�:"+pkcs11Provider.getInfo());
				int aaa = Security.addProvider(pkcs11Provider);
				Provider[]	Provider = Security.getProviders();
				System.out.println("�����ӬO�_�Q�ҥ�"+aaa);
				KeyStore smartCardKeyStore; 
				
				try {
					//Token Login �ʧ@ 
					String pin = "731009";
					smartCardKeyStore = KeyStore.getInstance("PKCS11");
					smartCardKeyStore.load(null, pin.toCharArray());
					
									
					// ���o�����ɮ�
					Enumeration aliasesEnum = smartCardKeyStore.aliases();			
					while (aliasesEnum.hasMoreElements()) {
					   String alias = (String)aliasesEnum.nextElement();
					   System.out.println("Alias: " + alias);
					   X509Certificate cert = (X509Certificate) smartCardKeyStore.getCertificate(alias);
					   
					   System.out.println("cert_SubjectDN: " + cert.getSubjectDN());
					   
					   PrivateKey privateKey = (PrivateKey) smartCardKeyStore.getKey(alias, null);
					   					   
					   if(alias.equals("cert1")){ //signature
						 //sign test
							String data = "Test Text (to be signed)";
							
							Signature sig = Signature.getInstance("SHA1withRSA", pkcs11Provider);
							System.out.println(sig.getProvider());
						    sig.initSign(privateKey);
						    sig.update(data.getBytes());
						    byte[] signatureBytes = sig.sign();
						    
						    sig.initVerify(cert);
						    sig.update(data.getBytes());
						    boolean verifyResult = sig.verify(signatureBytes);
						    if(true == verifyResult)
						    	System.out.println("PKCS#1 signature verify(through Certificate) ok");
						    else
						    	System.err.println("PKCS#1 signature verify(through Certificate) fail");
						    
					   }
					}
				} catch (KeyStoreException e) {
					System.out.println("1111_KeyStoreException");
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					System.out.println("NoSuchAlgorithmException");
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (CertificateException e) {
					System.out.println("CertificateException");
					// TODO Auto-generated catch block
					e.printStackTrace();
				}  catch (UnrecoverableKeyException e) {
					System.out.println("UnrecoverableKeyException");
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					System.out.println("InvalidKeyException");
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (SignatureException e) {
					System.out.println("SignatureException");
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (Exception  e) {
					
					StackTraceElement[] test = e.getStackTrace();
					Throwable aaawdqwa = e.fillInStackTrace();
					String dis = e.toString();
					System.out.println("Exception:"+e.getCause().getCause().getMessage());
					// System.out.println("Exception:"+e.getLocalizedMessage());
					if (e instanceof LoginException) {
						System.out.println("PKCS11Exception");
				         if ("CKR_PIN_INCORRECT".equals(e.getMessage())) {
			                	System.out.println("PIN?���?");
			                    //throw new DigiDocException(DigiDocException.ERR_TOKEN_LOGIN, "Invalid PIN", e);
			                }
			           }
					// TODO Auto-generated catch block
					//e.printStackTrace();
				}
				
				//���P����ثe�ϥΪ��귽
				Security.removeProvider(pkcs11ProviderName);
		        
		        
	        }else{
	        	System.out.println("�нT�{"+terminals.get(solt).getName()+"��Ū�d���O�_����m�d��");
	        }	
        }
	}

	public static long[] getSlotsWithTokens(String libraryPath) throws IOException{
        CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
        String functionList = "CHTSmartCard\r\n";

        initArgs.flags = 0;
        PKCS11 tmpPKCS11 = null;
        long[] slotList = null;
        try {
            try {
                tmpPKCS11 = PKCS11.getInstance(libraryPath, functionList, null , false);
            } catch (IOException ex) {
                ex.printStackTrace();
                throw ex;
            }
        } catch (PKCS11Exception e) {
            try {
                initArgs = null;
                tmpPKCS11 = PKCS11.getInstance(libraryPath, functionList, initArgs, true);
            } catch (IOException ex) {
               ex.printStackTrace();
            } catch (PKCS11Exception ex) {
               ex.printStackTrace();
            }
        }

        try {
            slotList = tmpPKCS11.C_GetSlotList(true);

            for (long slot : slotList){
                CK_TOKEN_INFO tokenInfo = tmpPKCS11.C_GetTokenInfo(slot);
                System.out.println("slot: "+slot+"\nmanufacturerID: "
                        + String.valueOf(tokenInfo.manufacturerID) + "\nmodel: "
                        + String.valueOf(tokenInfo.model));
            }
        } catch (PKCS11Exception ex) {
                ex.printStackTrace();
        } catch (Throwable t) {
            t.printStackTrace();
        }

        return slotList;

    }
	
	
	
}