#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "operatorinterface.h"

namespace Ui
{
class Encryption;

}

class Encryption : public QObject, OperatorInterface
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "hobbits.OperatorInterface.4.Encryption")
    Q_INTERFACES(OperatorInterface)

public:
    Encryption();

    OperatorInterface* createDefaultOperator() override;
    QString getName() override;

    void provideCallback(QSharedPointer<PluginCallback> pluginCallback) override;
    void applyToWidget(QWidget *widget) override;

    bool canRecallPluginState(const QJsonObject& pluginState) override;
    bool setPluginStateInUi(const QJsonObject &pluginState) override;
    QJsonObject getStateFromUi() override;

    int getMinInputContainers(const QJsonObject &pluginState) override;
    int getMaxInputContainers(const QJsonObject &pluginState) override;

    QSharedPointer<const OperatorResult> operateOnContainers(
            QList<QSharedPointer<const BitContainer> > inputContainers,
            const QJsonObject &recallablePluginState,
            QSharedPointer<ActionProgress> progressTracker) override;
    void previewBits(QSharedPointer<BitContainerPreview> container) override;
private slots:
    void requestRun();
private:
    Ui::Encryption *ui;
    QSharedPointer<PluginCallback> m_pluginCallback;
};

#endif // ENCRYPTION_H
