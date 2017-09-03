/*
 * hotp.cpp
 *
 *  Created on: 03-Sep-2017
 *  Author: Jaseem V V
 */

#include "hotp.h"
#include "sbreturn.h"
#include "hugse56.h"

#include <QDebug>
#include <iostream>

using namespace std;

HOTP::HOTP()
{
    int rc = SB_SUCCESS;
    rc = hu_GlobalCtxCreateDefault(&sbCtx);
    rc = hu_RegisterSbg56(sbCtx);
    rc = hu_InitSbg56(sbCtx);  //TODO: should be called only once in the lifetime of the application
}

QString HOTP::generate_hmac_sha1(QString sharedKey, QString inputData) {
	int rc = SB_SUCCESS;
	QByteArray key_ba = sharedKey.toUtf8();
	QByteArray input_ba = inputData.toUtf8();
	const unsigned char *key = reinterpret_cast<const unsigned char *>(key_ba.data());
	unsigned char* input_blk = reinterpret_cast<unsigned char*>(input_ba.data());
	unsigned char messageDigestHMAC[SB_HMAC_SHA1_160_TAG_LEN];

	qDebug() << "key_ba length: " << (size_t)key_ba.length();
	rc = hu_HMACSHA1Begin((size_t)key_ba.length(), key, NULL, &hmacContext, sbCtx);
	rc = hu_HMACSHA1Hash(hmacContext, input_ba.length(), input_blk, sbCtx);
	rc = hu_HMACSHA1End(&hmacContext, SB_HMAC_SHA1_160_TAG_LEN, messageDigestHMAC, sbCtx);
	return binToHex(messageDigestHMAC);
}

QString HOTP::binToHex(unsigned char *messageDigestHMAC) {
	QString digest;
	for (int i = 0; i < SB_HMAC_SHA1_160_TAG_LEN; ++i) {
		digest.append(QString("%1").arg(QString::number((uint)messageDigestHMAC[i], 16), 2, QChar('0')));
	}
	qDebug() << digest;
	return digest;
}

HOTP::~HOTP()
{
	hu_GlobalCtxDestroy(&sbCtx);
}

