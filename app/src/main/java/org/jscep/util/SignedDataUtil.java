/*
 * Copyright (c) 2009-2012 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jscep.util;

import java.security.cert.X509Certificate;

import org.spongycastle.cms.CMSException;
import org.spongycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.spongycastle.cms.SignerInformation;
import org.spongycastle.cms.SignerInformationStore;
import org.spongycastle.cms.SignerInformationVerifier;
import org.spongycastle.cms.jcajce.JcaSignerId;
import org.spongycastle.operator.ContentVerifierProvider;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.DigestCalculatorProvider;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * This class contains utility methods for manipulating SignedData objects.
 * 
 * @author David Grant
 */
public final class SignedDataUtil {
    /**
     * Private constructor to prevent instantiation.
     */
    private SignedDataUtil() {
    }

    /**
     * Checks if the provided signedData was signed by the entity represented by
     * the provided certificate.
     * 
     * @param sd
     *            the signedData to verify.
     * @param signer
     *            the signing entity.
     * @return <code>true</code> if the signedData was signed by the entity,
     *         <code>false</code> otherwise.
     */
    public static boolean isSignedBy(CMSSignedData sd, X509Certificate signer) {
	SignerInformationStore store = sd.getSignerInfos();
	SignerInformation signerInfo = store.get(new JcaSignerId(signer));
	if (signerInfo == null) {
	    return false;
	}
	CMSSignatureAlgorithmNameGenerator sigNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
	SignatureAlgorithmIdentifierFinder sigAlgorithmFinder = new DefaultSignatureAlgorithmIdentifierFinder();
	ContentVerifierProvider verifierProvider;
	try {
	    verifierProvider = new JcaContentVerifierProviderBuilder()
		    .build(signer);
	} catch (OperatorCreationException e) {
	    throw new RuntimeException(e);
	}
	DigestCalculatorProvider digestProvider;
	try {
	    digestProvider = new JcaDigestCalculatorProviderBuilder().build();
	} catch (OperatorCreationException e1) {
	    throw new RuntimeException(e1);
	}
	SignerInformationVerifier verifier = new SignerInformationVerifier(
		sigNameGenerator, sigAlgorithmFinder, verifierProvider,
		digestProvider);
	try {
	    return signerInfo.verify(verifier);
	} catch (CMSException e) {
	    return false;
	}
    }
}
