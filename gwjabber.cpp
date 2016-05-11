#include <mgr/mgrlog.h>
#include <mgr/mgrrpc.h>
#include <mgr/mgrproc.h>
#include <mgr/mgrtask.h>

#include <defines.h>
#include <gate/gatemodule.h>

#include <gloox/client.h>
#include <gloox/connectionlistener.h>
#include <gloox/error.h>
#include <gloox/message.h>
#include <gloox/messagehandler.h>
#include <gloox/connectiontcpclient.h>
#include <gloox/xhtmlim.h>

#define BINARY_NAME "gwjabber"

MODULE("notify");

namespace gate {

// Gloox based gateway
class JabberClient : public gloox::ConnectionListener, public gloox::LogHandler, public gloox::MessageHandler {
private:
	string m_ticket_format;
	bool m_recv;
	std::shared_ptr<gloox::Client> m_client;
	gloox::ConnectionTCPClient * m_conn;
	
public:
	JabberClient(const string& ticket_format = "", bool recv = false)
		: gloox::ConnectionListener()
		, gloox::LogHandler()
		, gloox::MessageHandler()
		, m_ticket_format(ticket_format)
		, m_recv(recv)
	{
		
	}
	
	virtual ~JabberClient()
	{
		if (m_client)
			m_client->disconnect();
	}
	
	void ProcessConnection()
	{
		int sock = m_conn->socket();
		
		fd_set sockset;
		FD_ZERO(&sockset);
		FD_SET(sock, &sockset);
		
		timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 1000000;
		
		while (select(sock + 1, &sockset, NULL, NULL, &timeout) == 1) {
			if (FD_ISSET(sock, &sockset))
				m_client->recv(1000000);
		}
		
		if (!m_client->authed() || m_client->state() != gloox::StateConnected || m_client->authError() != gloox::AuthErrorUndefined)
			throw mgr_err::Error("connect");
	}
	
	bool Login(const string& username, const string& password)
	{
		gloox::JID jid(username);
		m_client.reset(new gloox::Client(jid, password));
		
		m_client->logInstance().registerLogHandler(gloox::LogLevelDebug, gloox::LogAreaAll, this);
		m_client->registerConnectionListener(this);
		if (m_recv)
			m_client->registerMessageHandler(this);
		
		m_conn = new gloox::ConnectionTCPClient(m_client.get(), m_client->logInstance(), m_client->server());
		m_client->setConnectionImpl(m_conn);
		
		m_client->connect(false);
		
		while (m_client->state() == gloox::StateConnecting) {
			LogInfo("connecting...");
			mgr_proc::Sleep(200);
		}
		
		while (!m_client->authed() && m_client->authError() == gloox::AuthErrorUndefined && m_client->state() == gloox::StateConnected)
			ProcessConnection();

		LogInfo("connected to server: %s", m_client->server().c_str());
		
		return true;
	}

	void Send(const string& jabber, const string& message, const string& subject)
	{
		ProcessConnection();
		gloox::Message msg(gloox::Message::Chat, gloox::JID(jabber), message, subject);
		m_client->send(msg);
		ProcessConnection();
	}

	virtual void onConnect()
	{
		LogInfo("connected as %s", m_client->username().c_str());
	}
	
	virtual bool onTLSConnect(const gloox::CertInfo &info)
	{
		LogInfo("connected as %s", m_client->username().c_str());
		return true;
	}
	 
	virtual void onDisconnect(gloox::ConnectionError e)
	{
		LogInfo("disconnect code: %d", e);
	}
	
	virtual void onSessionCreateError( const gloox::Error* error ) 
	{
		LogInfo("session create error: %s", error->text().c_str());
	}
	
	virtual void handleLog(gloox::LogLevel level, gloox::LogArea area, const string& message)
	{
		Debug("%X %s", area, message.c_str());
	}
	
	virtual void handleMessage(const gloox::Message& msg, gloox::MessageSession* session = 0)
	{
		string message = msg.body();
		string jabber = msg.from().bare();
		
		mgr_db::QueryPtr user = sbin::DB()->Query("SELECT id, account, name FROM user WHERE jabber = " + sbin::DB()->EscapeValue(jabber));
		if (user->Eof()) {
			Send(jabber, "You are not registered!", "BILLmanager account");
			return;
		}
		
		if (m_ticket_format.empty() || !str::StartsWith(message, m_ticket_format.substr(0, 1))) {
			Send(jabber, "Not valid ticket id format!", "BILLmanager account");
			return;
		} else {
			int ticket_id = str::Int(str::Replace(str::GetWord(message), m_ticket_format.substr(0, 1), ""));
			mgr_db::QueryPtr ticket = sbin::DB()->Query("SELECT id FROM ticket WHERE id = " + str::Str(ticket_id) + " AND account_client = " + user->AsString("account"));
			if (ticket->Eof()) {
				Send(jabber, "Invalid ticket id!", "BILLmanager account");
				return;
			}

			try {
				sbin::ClientQuery("func=clientticket.edit&sok=ok&elid=" + str::Str(ticket_id) + "&su=" + str::url::Encode(user->AsString("name")) + "&message=" + str::url::Encode(message));
			} catch (mgr_err::Error& e) {
				Send(jabber, "Error: " + string(e.what()), "BILLmanager account");
			}
		}
	}
};

class Jabber : public Module {
public:
	Jabber()
		: Module(BINARY_NAME)
	{
	}
	
	virtual mgr_xml::Xml Features() const
	{
		mgr_xml::Xml out;
		mgr_xml::XmlNode features = out.GetRoot().AppendChild("features");
		features.AppendChild("feature").SetProp("name", GATE_CMD_FORM_TUNE);
		features.AppendChild("feature").SetProp("name", GATE_CMD_CHECK_CONNECTION);
		features.AppendChild("feature").SetProp("name", GATE_CMD_INGOING);
		features.AppendChild("feature").SetProp("name", GATE_CMD_OUTGOING);

		out.GetRoot().AppendChild("notify_module", "ntjabber");
		
		return out;
	}
	
	virtual void FormTune(mgr_xml::Xml& ses) const 
	{
		auto slist = ses.GetRoot().AppendChild("slist")
				.SetProp("name", "ticket_format");
		slist.AppendChild("val", "@id");
		slist.AppendChild("val", "#id");;
	}

	void CheckConnection(mgr_xml::Xml& ses) const
	{
		// Try connect to server
		mgr_xml::XmlString params(ses.GetRoot().FindNode("xmlparams"));
		string jabber = params.GetRoot().FindNode("jabber");
		string password = params.GetRoot().FindNode("password");
		
		JabberClient client;
		if (!client.Login(jabber, password))
			throw mgr_err::Error("connect");
	}

	mgr_xml::Xml Ingoing(mgr_xml::Xml& msg) const
	{
		string id = GateParam("id");
		mgr_task::LongTask task(mgr_file::ConcatPath("gate", mgr_proc::Escape(BINARY_NAME)), "jabber_recv_" + id);
		task.SetParam("--command");
		task.SetParam("jabber_recv");
		task.SetParam("--gate");
		task.SetParam(id);
		task.Start(mgr_task::LongTask::stRestart | mgr_task::LongTask::stImmediately);
		
		// Return to notify module if need
		mgr_xml::Xml out_xml;
		out_xml.GetRoot().AppendChild("ok");
		return out_xml;
	}

	virtual void Outgoing(mgr_xml::Xml& msg) const
	{
		JabberClient client;
		if (!client.Login(GateParam("jabber"), GateParam("password")))
			throw mgr_err::Error("connect");
		
		string jabber = msg.GetRoot().FindNode("jabber");
		string message = msg.GetRoot().FindNode("message");
		string subject = msg.GetRoot().FindNode("subject");
		
		client.Send(jabber, message, subject);
	}
	
	virtual void ProcessCommand(ModuleArgs& args) const 
	{
		if (!args.Command.Exists)
			return;
		
		Debug("command: %s", args.Command.AsString().c_str());
		
		if (args.Command.AsString() == "jabber_recv") {
			if (args.Gate.AsString().empty())
				throw mgr_err::Error("no_gate");
			
			auto lock = mgr_file::UniqueLock("jabber_recv_" + args.Gate.AsString());
			
			mgr_xml::XmlString gate(sbin::DB()->Query("SELECT xmlparams FROM gateway WHERE id = " + sbin::DB()->EscapeValue(args.Gate.AsString()))->Str());
			
			JabberClient client(gate.GetRoot().FindNode("ticket_format"), true);
			if (!client.Login(gate.GetRoot().FindNode("jabber"), gate.GetRoot().FindNode("password")))
				throw mgr_err::Error("connect");
			while (!sbin::TermSignalRecieved()) {
				client.ProcessConnection();
				mgr_proc::Sleep(1000);
			}
		}
	}
};

} // END NAMESPACE GATE

RUN_MODULE(gate::Jabber)
