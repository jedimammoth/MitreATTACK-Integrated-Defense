from stix2 import FileSystemSource
from stix2 import Filter
from itertools import chain

fs = FileSystemSource('./cti/enterprise-attack')
filt = Filter('type', '=', 'attack-pattern')
techniques = fs.query([filt])

def get_mitigation(src):
    return src.query([
        Filter('type', '=', 'course-of-action')
    ])

def get_all_groups(src):
    return src.query([
        Filter('type', '=', 'intrusion-set')
    ])

def get_group_by_alias(src, alias):
    return src.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])


def get_technique_by_group(src, stix_id):
    relations = src.relationships(stix_id, 'uses', source_only=True)
    external_id_response = src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in relations])
    ])
    mitigations = get_mitigation(fs)
    for adv in mygroups:
        for phase in attack_exploitation_lifecycle:
                tech_date = [[i['name'], i['kill_chain_phases'][0]['phase_name'], mitigation['description'], str(i['created']).split('T')[0].split()[0]] for i in external_id_response for mitigation in mitigations if stix_id['name']==adv and i['kill_chain_phases'][0]['phase_name']==phase and i['external_references'][0]['external_id']==mitigation['external_references'][0]['external_id']]
                for i in tech_date:
                        print '%s,%s,%s,%s' % (stix_id['name'], i[0], i[1], i[2])

mygroups = ['Lazarus Group']
attack_exploitation_lifecycle = ['initial-access','execution','persistence','defense-evasion','command-and-control','discovery','lateral-movement','collection','exfiltration']
groups = get_all_groups(fs)
group_names = [n["name"] for n in groups]
group_stix_ids = [get_group_by_alias(fs, alias)[0] for alias in group_names]
[get_technique_by_group(fs, group_stix_id) for group_stix_id in group_stix_ids]
