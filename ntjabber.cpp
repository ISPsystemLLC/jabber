#include <api/module.h>
#include <mgr/mgrlog.h>
#include <mgr/mgrproc.h>
#include <notify/notifymodule.h>
#include <notify/template.h>
#include <table/dbobject.h>

#define BINARY_NAME "ntjabber"

MODULE("notify");

namespace notify {

class Jabber : public Module
{
public:
	Jabber();
	virtual ~Jabber();

	virtual mgr_xml::Xml Features() const;
	virtual bool UserNotify(const string& filename) const;
	virtual void GetMessage(string gate_id) const;
};

Jabber::Jabber()
	: Module	(BINARY_NAME)
{
}

Jabber::~Jabber()
{
}

mgr_xml::Xml Jabber::Features() const
{
	mgr_xml::Xml xml;
	auto features = xml.GetRoot().AppendChild("features");
//	features.AppendChild("feature").SetProp("name", "html");
	xml.GetRoot().AppendChild("contact_type", "jabber");
	return xml;
}

bool Jabber::UserNotify(const std::string& filename) const
{
	mgr_xml::XmlFile data(filename);
	
	ForEachI(data.GetNodes("/doc/notify"), e) {
		string tmpl = e->FindNode("tmpl").Str();
		mgr_xml::Xml notice_xml = mgr_xml::XmlString(e->FindNode("notice_xml").Str());

		Debug("notice_xml:\n%s", notice_xml.Str(true).c_str());
		
		mgr_xml::XmlNode project = notice_xml.GetRoot().FindNode("project");
		mgr_xml::XmlNode noticeparams = notice_xml.GetRoot().FindNode("noticeparams");
		mgr_xml::XmlNode user = e->FindNode("user");

		string message = nttemplate::Transform(tmpl, notice_xml);
		ReplaceMacros(message, user);
		
		Debug("message: %s", message.c_str());
		if (message.empty())
			return true;
		
		const string jabber = user.FindNode("jabber").Str();
		
		Debug("jabber: %s", jabber.c_str());
		if (jabber.empty())
			return true;

		string subject = notice_xml.GetRoot().FindNode("subject").Str();
		if (subject.empty() && noticeparams)
			subject = noticeparams.FindNode("subject").Str();
		if (subject.empty())
			subject = e->FindNode("templatesubject").Str();

		ReplaceMacros(subject, user);
		
		StringSet attachments;
		ForEachI(notice_xml.GetNodes("/doc/attachments/attachment"), f) {
			attachments.insert(f->Str());
		}

		mgr_xml::Xml in_xml;
		in_xml.GetRoot().AppendChild("message", message);
		in_xml.GetRoot().AppendChild("subject", subject);
		in_xml.GetRoot().AppendChild("jabber", jabber);

		if (project) {
			ForEachQuery(sbin::DB(), "SELECT * FROM gateway "
							 "WHERE notify_module = '" BINARY_NAME "' AND "
								   "gateway_type = " + str::Str(table::Gateway::gwOutgoing) + " AND "
								   "active = 'ON' AND "
								   "project = " + sbin::DB()->EscapeValue(project.FindNode("id")), g) {
				mgr_xml::XmlNode gate = in_xml.GetRoot().AppendChild("gateway");

				for (size_t i = 0; i < g->ColCount(); ++i) {
					gate.AppendChild(g->ColName(i).c_str(), g->AsString(i));
				}

				mgr_proc::Execute gate_exec(mgr_file::ConcatPath("gate", mgr_proc::Escape(g->AsString("gateway_module"))) + " --command " GATE_CMD_OUTGOING, mgr_proc::Execute::efIn);
				gate_exec << in_xml.Str(true);
				gate_exec.Run();
				
				return true;
			}
		}
	}
	
	return true;
}

void Jabber::GetMessage(std::string gate_id) const
{
	ForEachQuery(sbin::DB(), "SELECT * FROM gateway "
							 "WHERE notify_module = '" BINARY_NAME "' AND "
								   "gateway_type = " + str::Str(table::Gateway::gwIngoing) + " AND "
								   "active = 'on'"
								   ""  + (str::Int(gate_id) ? " AND id = " + sbin::DB()->EscapeValue(gate_id) : ""), q) {
		mgr_xml::Xml in_xml;
		mgr_xml::XmlNode gate = in_xml.GetRoot().AppendChild("gateway");

		for (size_t i = 0; i < q->ColCount(); ++i) {
			gate.AppendChild(q->ColName(i).c_str(), q->AsString(i));
		}

		// Post data about gateway
		mgr_proc::Execute gate_exec(mgr_file::ConcatPath("gate", mgr_proc::Escape(q->AsString("gateway_module"))) + " --command " GATE_CMD_INGOING,
									mgr_proc::Execute::efIn);
		gate_exec.Run();
		gate_exec << in_xml.Str();
	}
}

}

RUN_MODULE(notify::Jabber)
