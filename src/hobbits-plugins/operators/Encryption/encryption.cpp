#include "encryption.h"
#include "ui_encryption.h"
#include <cipher.h>
#include <QDebug>
#include <QMessageBox>
#include <QToolTip>
#include <QObject>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QTime>
#include <QProcess>
#include <QFileInfo>

Encryption::Encryption() :
    ui(new Ui::Encryption())
{

}

OperatorInterface* Encryption::createDefaultOperator()
{
    return new Encryption();
}

//Return name of operator
QString Encryption::getName()
{
    return "Encryption";
}

void Encryption::provideCallback(QSharedPointer<PluginCallback> pluginCallback)
{
    // the plugin callback allows the self-triggering of operateOnContainers
    m_pluginCallback = pluginCallback;
}

bool Encryption::canRecallPluginState(const QJsonObject &pluginState)
{
    //if pluginState does not have required fields, return false
    if(pluginState.isEmpty() == true){
        return false;
    }
    if(!pluginState.contains("key") || !pluginState.value("key").isString()){
        return false;
    }
    return true;
}

bool Encryption::setPluginStateInUi(const QJsonObject &pluginState)
{
    if (!canRecallPluginState(pluginState)) {
        return false;
    }

    // Set the UI fields based on the plugin state
    ui->le_key->setText(pluginState.value("key").toString());
    ui->rb_encrypt->setChecked(true);
    ui->rb_decrypt->setChecked(false);
    ui->rb_ascii->setChecked(false);
    ui->rb_hex->setChecked(false);
    ui->rb_binary->setChecked(false);
    return true;
}

QJsonObject Encryption::getStateFromUi()
{
    QJsonObject pluginState;

    //Pull data from the input fields and input them into pluginState

    pluginState.insert("key", ui->le_key->text());
    return pluginState;
}

int Encryption::getMinInputContainers(const QJsonObject &pluginState)
{
    Q_UNUSED(pluginState)
    return 1;
}

int Encryption::getMaxInputContainers(const QJsonObject &pluginState)
{
    Q_UNUSED(pluginState)
    return 1;
}

QSharedPointer<const OperatorResult> Encryption::operateOnContainers(
        QList<QSharedPointer<const BitContainer> > inputContainers,
        const QJsonObject &recallablePluginState,
        QSharedPointer<ActionProgress> progressTracker)
{
    QSharedPointer<OperatorResult> result(new OperatorResult());
    //Perform bit operations here
    QSharedPointer<const OperatorResult> nullResult;
    if (inputContainers.size() != 1) {
        return nullResult;
    }

    /*connect(ui->rb_RSA, SIGNAL(checked()), this, SIGNAL(rsaClicked()));
    connect(ui->rb_xor, SIGNAL(checked()), this, SIGNAL(xorClicked()));*/

    QSharedPointer<const BitArray> inputBits = inputContainers.takeFirst()->bits();

    //Perform bit operations here
    if(!canRecallPluginState(recallablePluginState)){
        return OperatorResult::error("Please fill in the required in the proper format.");
    }
    if(ui->rb_xor->isChecked()){
        QString keyString = recallablePluginState.value("key").toString();
        //keyString length needs to be less than or equal to 128 becuase the plugin crashes otherwise
        //Generate a key for the user if the user didn't enter one
        QByteArray key_byte;
        QSharedPointer<BitArray> key;
        if(keyString.isEmpty() && ui->rb_encrypt->isChecked()){
            key = QSharedPointer<BitArray>(new BitArray(8));
            for(int i = 0; i < key->sizeInBits(); i++){
                qsrand(QTime::currentTime().msec());
                qint8 randNum = rand() % 2 + 0;
                key->set(i, randNum);
                keyString += QString().setNum(randNum);
            }
            ui->le_key->setText(keyString);
        }else if(keyString.isEmpty() && ui->rb_decrypt->isChecked()){
            return OperatorResult::error("Enter a key to decrypt your data");
        }else if(ui->rb_hex->isChecked()){
            key_byte = QByteArray::fromHex(keyString.toLatin1());
            key = QSharedPointer<BitArray>(new BitArray(key_byte, key_byte.size()*8));
        }else if(ui->rb_ascii->isChecked()){
            key_byte = QByteArray(keyString.toLatin1());
            key = QSharedPointer<BitArray>(new BitArray(key_byte, key_byte.size()*8));
        }else if(ui->rb_binary->isChecked()){
            key = QSharedPointer<BitArray>(new BitArray(keyString.length()));
            for(int i = 0; i < keyString.length(); i++){
                if(keyString.at(i) == '0'){
                    key->set(i, 0);
                }else if(keyString.at(i) == '1'){
                    key->set(i, 1);
                }else{
                    return OperatorResult::error("Invalid input. Please Double check the input fields.");
                }
            }
        }else if(keyString.length() > 128 || keyString.length() > inputBits->sizeInBits()){
            return OperatorResult::error("The key is too long. Key length should be less than or equal to 128 characters.");
        }else if(!(ui->rb_binary->isChecked() || ui->rb_ascii->isChecked() || ui->rb_hex->isChecked())){
            return OperatorResult::error("Please select what format your key is in (Hex/ASCII/Binary)");
        }else if(!(ui->rb_encrypt->isChecked() || ui->rb_decrypt->isChecked())){
            return OperatorResult::error("Please select whether you want to encrypt or decrypt the data");
        }
        //make output bits pointer to bitarray
        QSharedPointer<BitArray> outputBits = QSharedPointer<BitArray>(new BitArray(inputBits->sizeInBits()));
        //Declare variables for calculations
        //qint8 keyVal;
        qint64 bitsProcessed = 0;
        int lastPercent = 0;
        //do the doodoo
        for(int i = 0; i < inputBits->sizeInBits(); i++){
            qint8 indexKey = i % key->sizeInBits();
            qint8 xorVal = key->at(indexKey) ^ inputBits->at(i);
            outputBits->set(i, xorVal);
            bitsProcessed = i;
            if (bitsProcessed > 0) {
                int nextPercent = int(double(bitsProcessed) / double(inputBits->sizeInBits()) * 100.0);
                if (nextPercent > lastPercent) {
                    lastPercent = nextPercent;
                    progressTracker->setProgressPercent(nextPercent);
                }
            }
         }

         if (progressTracker->getCancelled()) {
            auto cancelledPair = QPair<QString, QJsonValue>("error", QJsonValue("Processing cancelled"));
            auto cancelled = (new OperatorResult())->setPluginState(QJsonObject({cancelledPair}));
            return QSharedPointer<const OperatorResult>(cancelled);
         }

        QSharedPointer<BitContainer> outputContainer = QSharedPointer<BitContainer>(new BitContainer());

        outputContainer->setBits(outputBits);

        result->setOutputContainers({outputContainer});
        result->setPluginState({recallablePluginState});
        return result;
    //return OperatorResult::error("Plugin operation is not plainimplemented!");
    //return OperatorResult::result({outputContainer}, recallablePluginState);
    }else if(ui->rb_RSA->isChecked()){
        char *data = new char[inputBits->sizeInBytes() + 1];
        qint32 bytes = inputBits->readBytes(data, 0, inputBits->sizeInBytes());
        //QByteArray input2;
        //input2.append((const char*)&bytes, sizeof(bytes));
        QByteArray input = QByteArray(data, bytes);
        Cipher cwrapper;

        QFileInfo check_file("private.pem");
        QFileInfo check_file_two("public.pem");

       if(!(check_file.exists() && check_file.isFile())){
            QProcess::execute("openssl genrsa -out private.pem 2048");
        }
        if(!(check_file_two.exists() && check_file_two.isFile())){
            QProcess::execute("openssl rsa -in private.pem -out public.pem -outform PEM -pubout");
        }

        RSA* publickey = cwrapper.getPublicKey("public.pem");
        RSA* privatekey = cwrapper.getPrivateKey("private.pem");


        QSharedPointer<BitContainer> outputContainer = QSharedPointer<BitContainer>(new BitContainer());
        //QByteArray encrypted = cwrapper.encryptRSA(publickey, input);
        //QByteArray decrypted = cwrapper.decryptRSA(privatekey, encrypted);

        if(ui->rb_encrypt->isChecked()){
           QByteArray encrypted = cwrapper.encryptRSA(publickey, input);
           outputContainer->setBits(QSharedPointer<BitArray>(new BitArray(encrypted, encrypted.size()*8)));

        }else if(ui->rb_decrypt->isChecked()){
           QByteArray decrypted = cwrapper.decryptRSA(privatekey, input);
           outputContainer->setBits(QSharedPointer<BitArray>(new BitArray(decrypted, decrypted.size()*8)));
        }

        //cwrapper.freeRSAKey(publickey);
        //cwrapper.freeRSAKey(privatekey);

        result->setOutputContainers({outputContainer});
        result->setPluginState({recallablePluginState});
        return result;
    }
    return nullResult;
}
void Encryption::previewBits(QSharedPointer<BitContainerPreview> container)
{
    Q_UNUSED(container)
    // optionally use the current container to prepare the UI or something
}

/*void Encryption::switchPage(int num)
{
    UIs->setCurrentIndex(num);
}*/

void Encryption::requestRun()
{
    if (!m_pluginCallback.isNull()) {
        m_pluginCallback->requestOperatorRun(getName());
    }
}

void Encryption::applyToWidget(QWidget *widget)
{
    ui->setupUi(widget);
    //connect(ui->btnInfo, SIGNAL(clicked()), this, SLOT(showHelp()));
    connect(ui->le_key, SIGNAL(returnPressed()), this, SLOT(requestRun()));
    connect(ui->rb_xor, SIGNAL(toggled(bool)), this, SLOT(checkXorUi(bool)));
    connect(ui->rb_RSA, SIGNAL(toggled(bool)), this, SLOT(checkRsaUi(bool)));
}

void Encryption::checkRsaUi(bool checked)
{
    int currentIndex = ui->UIs->currentIndex();
    if(currentIndex < ui->UIs->count()){
         ui->UIs->setCurrentIndex(0); // page1
    }
}

void Encryption::checkXorUi(bool checked)
{
    int currentIndex = ui->UIs->currentIndex();
    if(currentIndex < ui->UIs->count()){
         ui->UIs->setCurrentIndex(1); // page1
    }
}
