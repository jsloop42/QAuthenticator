/*
 * hotp.h
 *
 *  Created on: 03-Sep-2017
 *  Author: Jaseem V V
 */

#ifndef HOTP_H_
#define HOTP_H_

#include "huctx.h"
#include "husha1.h"

#include <QObject>

class HOTP
{
public:
    HOTP();
    QString generate_hmac_sha1(QString key, QString input_data);
    virtual ~HOTP();
private:
    sb_GlobalCtx sbCtx;
    sb_Context hmacContext;
    QString binToHex(unsigned char *messageDigestHMAC);
};

#endif /* HOTP_H_ */
