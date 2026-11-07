# Privacy/legal position of device fingerprinting for bot defence, and the client-side security trust boundary

Status: research notes as of 2026-11-07. Not legal advice; a report using this should say so and advise qualified counsel before any public compliance claim.

How sources were read. "Primary, read" means I read the relevant passage in the document itself: EDPB 2/2023 v2.0, WP194, WP224, DSK OH v1.1 and v1.2, CNIL SAN-2023-003 (English version hosted by EDPB), Council ST 14756/26, the Commission proposal's Art. 88a, DUAA Sch. 12, BVwG W298 2274626-1, Breyer, Planet49, and CNIL FAQ Q17 (via a fetch summary with excerpts). The ICO's own pages returned HTTP 403 throughout, so all ICO guidance wording below is second-hand and flagged as such.

## Q1. Does reading device data for fingerprinting need consent, and is the "strictly necessary" exemption available for security/bot defence?

### Takeaway
Yes, Art. 5(3) is triggered whenever client code reads device properties and any of that data or a derivation of it leaves the device, even if the operator is first-party and self-hosted. Consent is then needed unless an exemption applies. Regulators support a narrow exemption for security that is user-centric, tied to a service the user requested, and sole-purpose. But it is not settled for general bot detection: the sources conflict, and the only court ruling on point (Austria, about Google reCAPTCHA) is hostile. "No consent needed" is a defensible risk position under specific conditions, not an established fact.

### Cited Findings

**EU baseline**
- EDPB Guidelines 2/2023 final is **Version 2.0, adopted 7 October 2024** (the EDPB page lists 16 October 2024, which appears to be the publication date; some law-firm reports use that date). — [EDPB v2.0 PDF](https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202302_technical_scope_art_53_eprivacydirective_v2_en_0.pdf); [EDPB page](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22023-technical-scope-art-53-eprivacy-directive_en)
- Fingerprinting falls within Art. 5(3) (¶2, confirming WP29 Opinion 9/2014). JavaScript that instructs the browser to send targeted information "clearly falls within the scope" (¶33). HTTP context data such as `accept` or user agent, when relied on to collect information including for fingerprinting, "can lead to" application of Art. 5(3) (¶43). — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202302_technical_scope_art_53_eprivacydirective_v2_en_0.pdf)
- IP addresses trigger Art. 5(3) only where they originate from the terminal equipment. The EDPB says this covers a static outbound IPv4 from a user's router and IPv6, and not systematically CGNAT. Unless the entity can ensure otherwise, it must take the Art. 5(3) steps (¶55). The heading of this section concerns tracking based on IP only. — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202302_technical_scope_art_53_eprivacydirective_v2_en_0.pdf)
- **The EDPB guidelines expressly do not decide exemptions** (¶4, ¶40). ¶56 stresses that applicability "does not systematically mean that consent needs to be collected". Any claim that the EDPB "cleared" or "banned" CAPTCHA fingerprinting is wrong. — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202302_technical_scope_art_53_eprivacydirective_v2_en_0.pdf)
- Art. 5(3) applies whether or not the information is personal data (Planet49, C-673/17, 1 Oct 2019, ¶¶68-71). Consent cannot be a pre-ticked box; the information to users must include cookie duration and third-party access. — [CJEU C-673/17](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62017CJ0673)
- **The closest authoritative EU-level text on security fingerprinting is WP29 Opinion 9/2014 §7.5** (adopted 25 Nov 2014). The user-centric security exemption "would also apply to device fingerprinting", but not to "the security of websites or third party services that have not been explicitly requested by the user". Data "may not be used for any secondary purposes", and safeguards must prevent secondary use of data "typically kept in server security logs". Multi-purpose fingerprints are exempt only if all purposes are individually exempt. — [WP224](https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2014/wp224_en.pdf)
- WP29 Opinion 04/2012 §3.3 is the origin of this rule. It covers cookies for "increasing the security of the service that has been explicitly requested by the user", for example repeated failed logins or "similar mechanisms designed to protect the login system from abuses". — [WP194](https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2012/wp194_en.pdf)

**Germany**
- § 25 TDDDG requires consent for storage or access, except where the sole purpose is transmission, or where access is strictly necessary ("unbedingt erforderlich") to provide a digital service the user expressly wishes. — [§ 25 TDDDG](https://www.gesetze-im-internet.de/ttdsg/__25.html)
- **The current DSK guidance is "OH Digitale Dienste" Version 1.2, November 2024** (not the widely cited 2021/2022 OH Telemedien). — [DSK OH v1.2](https://datenschutzkonferenz-online.de/media/oh/OH_Digitale_Dienste.pdf)
- DSK v1.2: actively reading device properties with JavaScript and sending them to a server to build a fingerprint is "Zugriff" (Rn. 24). Later processing must separately satisfy the GDPR (Rn. 25). — [DSK OH v1.2](https://datenschutzkonferenz-online.de/media/oh/OH_Digitale_Dienste.pdf)
- **Supportive DSK language:** systems for "nutzerorientierte Betrugsprävention und IT-Sicherheit" serve both users and operator and "können dem Basisdienst zugerechnet werden" (Rn. 74). User-centric security cookies, including mechanisms protecting the login system against abuse, can be strictly necessary (Rn. 83). — [DSK OH v1.2](https://datenschutzkonferenz-online.de/media/oh/OH_Digitale_Dienste.pdf)
- **Limiting DSK language:** a blanket "security cookie" label is insufficient, and the exception does not extend to security of third-party services not expressly requested (Rn. 83). Who can access the information is strictly examined (Rn. 82). Additional functions are "wished" only when explicitly used, for example filling in a form, not merely because the site was opened (Rn. 76). — [DSK OH v1.2](https://datenschutzkonferenz-online.de/media/oh/OH_Digitale_Dienste.pdf)
- § 25 has only two routes, consent or exemption, with no balancing of interests. A legitimate-interest assessment under Art. 6(1)(f) cannot automatically establish § 25(2) no. 2 (Rn. 68-69). — [DSK OH v1.2](https://datenschutzkonferenz-online.de/media/oh/OH_Digitale_Dienste.pdf)
- **A safe-harbour argument has weakened.** DSK v1.1 (Dec 2022) Rn. 21 said information transmitted inevitably on page load (public IP, URL, User-Agent, language) is not "Zugriff". A text search of v1.2 finds no "User-Agent", "Header" or "zwangsläufig" passage in that section, so the carve-out appears to have been dropped. Compare EDPB ¶¶43, 55. — [DSK OH v1.1](https://www.datenschutz.bremen.de/sixcms/media.php/13/20221205_oh_Telemedien_2021_Version_1_1_Vorlage_104_DSK_final.pdf); [DSK OH v1.2](https://datenschutzkonferenz-online.de/media/oh/OH_Digitale_Dienste.pdf)
- German practitioner opinion is split on whether bot protection is technically necessary. These are reader comments on a legal blog, seen only through a search summary that did not tie each view to a specific page, so treat this as anecdotal. — [it-recht-kanzlei comment](https://www.it-recht-kanzlei.de/Kommentar/20804/Spitzenpreise.php); [comment on Friendly Captcha](https://www.it-recht-kanzlei.de/Kommentar/16120/Friendly_Captcha.php)

**France**
- **CNIL FAQ Q17 (page dated 29 April 2026), the most directly on-point regulator statement.** Consent is not needed where the tool's sole purpose is securing the site or an authentication mechanism for the users' benefit. Consent is needed where reads or writes also serve other purposes, with reCAPTCHA named as an example. Deployers should check the provider's terms. Because refusal would let bots bypass a consent-based tool, CNIL recommends alternatives that do not need consent. — [CNIL FAQ](https://www.cnil.fr/fr/cookies-et-autres-traceurs/regles/cookies/FAQ)
- **CNIL Cityscoot, SAN-2023-003 (16 March 2023), €125,000 overall.** ¶86: an exemption can be claimed when operations are "for the sole purpose of securing an authentication mechanism for the benefit of users", citing SAN-2021-013, but not when they "also pursue other purposes". reCAPTCHA failed because it "also allows analysis operations by Google". ¶¶84-85: the site publisher chose the tool and is responsible under Art. 82. ¶¶88-89: information and consent were required, and a generic privacy-policy statement was insufficient. — [Decision, English version](https://www.edpb.europa.eu/system/files/2023-08/fr_sa_2023-03-decisionpublic.pdf)
- Reported apportionment: €25,000 of the Cityscoot fine for cookies/reCAPTCHA, and NS Cards France (29 Dec 2023) €105,000 total with €15,000 for reCAPTCHA. This comes from one vendor blog and I did not confirm it in primary text. — [flinkform](https://flinkform.de/blog/recaptcha-dsgvo-rechtsrisiko)
- **Conflicting CNIL signal.** Law-firm reporting of CNIL's 22 July 2026 FAQ on its email-pixel recommendation quotes "the security exemption does not cover fraud prevention in general (e.g., bot detection)", limiting it to user-centred measures such as authentication and password resets. This is about pixels, not CAPTCHAs, and I read it second-hand. — [Norton Rose Fulbright](https://connections.nortonrosefulbright.com/post/102o01q/tracking-pixels-in-emails-a-cnil-recommendation-to-clarify-practices-and-secure)
- CNIL's general cookie guidance exempts trackers securing authentication, "par exemple en limitant les tentatives d'accès robotisées ou inattendues". — [CNIL guidance](https://www.cnil.fr/fr/cookies-et-autres-traceurs/regles/cookies/comment-mettre-mon-site-web-en-conformite)

**Austria**
- **BVwG, 13 Sept 2024, W298 2274626-1** (political party website, `_GRECAPTCHA` cookie). "Die Implementierung von reCAPTCHA ist für den Betrieb der Website technisch nicht notwendig". The court therefore found no legitimate interest and held that consent was required, applying ePrivacy Art. 5(3), Planet49, Art. 6(1)(f) and the C-252/21 necessity test. — [RIS](https://www.ris.bka.gv.at/Dokument.wxe?Abfrage=Bvwg&Dokumentnummer=BVWGT_20240913_W298_2274626_1_00)
- The brief asked about "LG Vienna". I found no LG Wien decision on CAPTCHA; the Austrian authority located is this BVwG ruling, upholding the DSB's assessment per a law-firm summary. — [Elbdeich-IT](https://www.elbdeich-it.de/blog/urteil-zum-datenschutz-oesterreichisches-bvwg-untersagt-recaptcha-einsatz-ohne-zustimmung.html)

**UK**
- DUAA 2025 s.112 and Sch. 12 insert PECR Sch. A1. Para 4(1) disapplies the rule where "strictly necessary" for a requested information society service. **Para 4(2) examples expressly include** "to prevent or detect fraud in connection with the provision of the service requested", technical faults, and terminal-equipment security. Para 4 contains no information or opt-out condition, unlike the statistics and appearance exceptions in paras 5-6. — [DUAA Sch. 12](https://www.legislation.gov.uk/ukpga/2025/18/schedule/12)
- Sch. 12 was commenced by SI 2026/82 (made 29 Jan 2026), reported in force 5 Feb 2026. — [SI 2026/82](https://legislation.gov.uk/uksi/2026/82); [Kennedys](https://www.kennedyslaw.com/en/thought-leadership/article/2026/the-data-use-and-access-act-2025-commencement-dates-and-planned-guidance-for-2026)
- The ICO's final Storage and Access Technologies guidance is reported as published 29 April 2026 and covers fingerprinting even where nothing is visibly stored. — [SCL](https://www.scl.org/ico-publishes-final-storage-and-access-technologies-guidance/); [Aphaia](https://aphaia.co.uk/ico-publishes-final-guidance-on-storage-and-access-technologies-and-signals-continued-enforcement-on-online-tracking-practices/)
- Second-hand quotations of the ICO: the fraud exception applies only if data is used "only" for that purpose; click-fraud detection counts as advertising and needs consent; in Dec 2024 the ICO called Google's allowing of fingerprinting for ad tech "irresponsible" and "not a fair means of tracking users online". The publisher is AI-assisted and secondary, so verify against ico.org.uk. — [NHIMG](https://nhimg.org/device-intelligence-and-fingerprinting-guide); [DLA Piper on the Dec 2024 statement](https://privacymatters.dlapiper.com/2025/01/googles-u-turn-on-device-fingerprinting-icos-response-and-subsequent-guidance/)
- PECR penalties are reported as raised to £17.5m or 4% of turnover. — [ZwillGen](https://www.zwillgen.com/eu-uk/ico-cookie-crackdown-2-icos-new-storage-access-technologies-guidance/)

**Digital Omnibus (2025/0360 COD): not law**
- Commission proposal COM(2025) 837, proposed GDPR Art. 88a(3): access without consent is lawful "to the extent it is necessary" for, among others, "(d) maintaining or restoring the security of a service provided by the controller and requested by the data subject or the terminal equipment used for the provision of such service". It would apply 6 months after entry into force. — [COM(2025) 837](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:52025PC0837)
- **Council mandate ST 14756/26 (outcome of proceedings dated 22 Oct 2026; Coreper agreed 21 Oct per commentary)** rewrites ePrivacy Art. 5(3) rather than creating Art. 88a. Exempt only if "solely related to and strictly necessary for": "(b) providing a service, including its functionality, explicitly requested by the subscriber or user"; "(e) maintaining or restoring the technical security of the means strictly necessary for the provision of a service requested by the subscriber or user or the technical security of the terminal equipment". Recital 44b calls it a "limitative list". Recital 44f requires measures to be "strictly necessary and proportionate" and says security "should include in particular cybersecurity". Member States would have 24 months to transpose. — [ST 14756/26](https://data.consilium.europa.eu/doc/document/ST-14756-2026-INIT/en/pdf)
- Caution on that text: it uses track-changes formatting and my text extraction merges deletions and insertions. Deletion of Art. 88a/88b is confirmed by two commentaries, not by my own reading of the strikethrough. — [EU Internet Policy](https://euinternetpolicy.wordpress.com/2026/10/23/the-councils-digital-omnibus-mandate-what-it-would-change-in-the-gdpr/); [Legal247](https://legal247.no/en/insights/digital-omnibus-gdpr/)
- Status: trackers report no Parliament position (ITRE-LIBE "awaiting committee decision" on 28 Oct 2026) and no trilogues yet. One outlier reports a provisional agreement on 7 May 2026; that conflicts with the Council document's mandate stage and should be disregarded unless confirmed. — [EU Digital Policy tracker](https://eudigitalpolicy.eu/instruments/data-omnibus/); [outlier](https://pasqualepillitteri.it/en/news/25616/digital-omnibus-explained-cookies-gdpr-ai)
- EDPB-EDPS Joint Opinion (Feb 2026) supports simplification but raises significant concerns, notably on narrowing the definition of personal data. — [EDPB news](https://www.edpb.europa.eu/news/digital-omnibus-edpb-and-edps-support-simplification-and-competitiveness-while-raising-key_en)

### Inferences
- **Self-hosting removes the ground CNIL actually relied on** (provider reuse, ¶86), but not the BVwG's ground. The BVwG's stated reasoning, "technically not necessary for operating the website", is not limited to third parties and could be applied to a self-hosted tool. Its facts did involve Google, and a page-load cookie on a party website with no protected action, which makes it distinguishable.
- The strongest position combines these conditions: (a) the widget runs only on a protected action the user initiates (login, registration, password reset, form submit), not page-wide; (b) the sole purpose is abuse defence for that service; (c) no secondary use, analytics, cross-site reputation or vendor telemetry; (d) the minimum signals needed; (e) signals are short-lived; (f) a documented necessity assessment shows why less intrusive means are insufficient. Condition (a) follows from DSK Rn. 76 and WP224 §7.5.
- **Grading of exemption strength, most to least defensible:**
  1. Login and credential-abuse defence, explicitly supported by WP194, DSK Rn. 83 and CNIL ¶86.
  2. Password reset and account creation, per CNIL's user-centred measures.
  3. Contact forms and comment forms, supported by the general wording of CNIL Q17 and DSK Rn. 74, but contested.
  4. Scalping or general site-wide bot scoring, the weakest; the reported CNIL 2026 pixel FAQ cuts against it.
- The strict necessity test is itself a design constraint. If PoW plus server-side rate limiting is adequate for a deployment, an operator struggles to show that active fingerprinting is "strictly" necessary. This favours **escalation**: fingerprint only when lighter signals indicate risk, and default to the no-read mode. DSK Rn. 81 (no need for individualising identifiers where non-identifying values suffice) points the same way by analogy.
- Omnibus effect, if the Council text survives: an explicit security limb would help, but "technical security of the means strictly necessary" plus "solely related to and strictly necessary" may be narrower than the Commission's "security of a service", and it is unclear whether spam or scalping counts as "technical security". Do not market against the Omnibus. Earliest practical effect under the Council's approach is roughly 24 months after adoption.
- UK is the friendliest regime because "prevent or detect fraud" is statutory text, though spam or generic bot traffic may not be "fraud", so operators would rely on the general strictly-necessary limb or the terminal-equipment limb.

### Gaps
- I found **no decision or fine concerning hCaptcha, and no German court ruling on CAPTCHA**. A search summary reported BayLDA advising operators to examine alternatives to reCAPTCHA, but I could not pin that to a primary document. Nothing found on self-hosted CAPTCHA specifically: the question looks untested.
- Primary wording of ICO guidance could not be read (HTTP 403). CNIL's 22 July 2026 pixel FAQ was not read directly.
- Whether the BVwG ruling is final or appealed was not established.
- Whether national regulators other than France, Germany, Austria and the UK have CAPTCHA-specific statements was not surveyed.
- The EDPB may issue further guidance; nothing newer on Art. 5(3) exemptions was found.

## Q2. GDPR Art. 6(1)(f), Recital 47/49, and the CJEU cases (Breyer, SRB)

### Takeaway
Art. 5(3)/§ 25 governs the read; the GDPR separately governs what happens afterwards. Legitimate interest is the natural basis for subsequent processing of security signals, but it cannot substitute for an Art. 5(3) exemption, and necessity is read strictly.

### Cited Findings
- **Breyer, C-582/14:** a dynamic IP address is personal data for an online media provider that has legal means to identify the user with data held by the ISP (¶49, operative part 1). A provider may have a legitimate interest in ensuring continued operability of its site (¶60), and national law cannot categorically exclude that balancing (¶¶61-64). — [CJEU C-582/14](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:62014CJ0582)
- Recital 49: processing "to the extent strictly necessary and proportionate" for network and information security can be a legitimate interest; examples include preventing unauthorised access and stopping denial-of-service attacks. The named actors are public authorities, CERTs/CSIRTs, communications providers and security technology providers. — [GDPR Recital 49](https://gdpr-info.eu/recitals/no-49/)
- Recital 47: processing "strictly necessary for the purposes of preventing fraud" also constitutes a legitimate interest; reasonable expectations of data subjects are part of the assessment. — [GDPR Recital 47](https://gdpr-info.eu/recitals/no-47/)
- BVwG, citing C-252/21, applied the test that processing must stay within what is "unbedingt notwendig" for the legitimate interest. — [RIS](https://www.ris.bka.gv.at/Dokument.wxe?Abfrage=Bvwg&Dokumentnummer=BVWGT_20240913_W298_2274626_1_00)
- DSK: under § 25 there is no balancing; an Art. 6(1)(f) assessment does not establish the exemption, and swapping legal bases in a privacy notice is not enough (Rn. 68-69). — [DSK OH v1.2](https://datenschutzkonferenz-online.de/media/oh/OH_Digitale_Dienste.pdf)
- EDPB Guidelines 1/2024 on legitimate interest were published 9 Oct 2024 as a consultation draft (until 20 Nov 2024). I could not confirm a final version; some vendor blogs wrongly call the draft final. The draft addresses fraud prevention and network security, though one respondent calls the fraud passages too succinct. — [Matheson](https://www.matheson.com/insights/detail/edpb-publishes-draft-guidelines-on-legitimate-interests); [Connect Europe](https://connecteurope.org/insights/position-papers/response-edpb-guidelines-data-processing-based-legitimate-interest)

### Inferences
- A two-layer record is needed: (1) the Art. 5(3)/§ 25 exemption analysis, and (2) a separate legitimate interests assessment for the GDPR layer. A vendor document that covers only LIA is incomplete under German guidance.
- Art. 21 objection rights apply when relying on 6(1)(f); a security-oriented answer (compelling legitimate grounds) plus an alternative path is the practical response, not an opt-out that bots would use. This parallels CNIL's Q17 point that refusal defeats the tool.

### Gaps
- Whether a hard block based on an automated bot score is "automated decision-making" under Art. 22 (and how SCHUFA, C-634/21, bears on it) was not researched. Treat as an open question; a human or alternative path reduces the exposure.
- The final status of EDPB Guidelines 1/2024 is unconfirmed: the EDPB guideline page URLs I tried returned 404.

## Q3. Does fully local processing with no third-party transfer change the analysis? Controller obligations and data minimisation

### Takeaway
"Local" helps only if nothing derived from the device data leaves it. As soon as a score, verdict, or hash is sent, Art. 5(3) applies again. "No third party" materially improves the exemption and GDPR positions but does not remove them: the site operator is the controller. Hashed fingerprints used to recognise a device remain personal data for that operator.

### Cited Findings
- EDPB ¶44: browser processing of information inside the device is not "gaining of access" "as long as the information does not leave the device, but when this information or any derivation of this information is accessed, Article 5(3) ePD would apply". — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202302_technical_scope_art_53_eprivacydirective_v2_en_0.pdf)
- EDPB ¶53: if processed information is "sent back over the network to a server", this is gaining of access, and "the fact that this information is being produced locally does not preclude the application of Article 5(3) ePD". — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202302_technical_scope_art_53_eprivacydirective_v2_en_0.pdf)
- EDPB ¶34: the instructing entity and the receiving entity need not be the same, so first-party or third-party structure does not determine applicability. — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202302_technical_scope_art_53_eprivacydirective_v2_en_0.pdf)
- Publisher responsibility: the site owner who chose the tool is responsible under Art. 82 even for the provider's operations (CNIL ¶¶84-85); the BVwG reached a similar result per a summary. — [CNIL decision](https://www.edpb.europa.eu/system/files/2023-08/fr_sa_2023-03-decisionpublic.pdf); [Elbdeich-IT](https://www.elbdeich-it.de/blog/urteil-zum-datenschutz-oesterreichisches-bvwg-untersagt-recaptcha-einsatz-ohne-zustimmung.html)
- DSK defines browser fingerprinting as forming a "möglichst eindeutigen und langlebigen (Hash-)Werts", so hashing is treated as a form of fingerprint rather than an exit from it (Rn. 23). Using it requires GDPR compliance when personal data is involved (Rn. 25). — [DSK OH v1.2](https://datenschutzkonferenz-online.de/media/oh/OH_Digitale_Dienste.pdf)
- **EDPS v SRB, C-413/23 P (4 Sept 2025):** pseudonymised data is not automatically personal for every holder; it depends on the recipient's reasonable means of re-identification. For the entity holding the key, it remained personal. — [datenschutz-notizen](https://www.datenschutz-notizen.de/pseudonymised-data-not-always-personal-according-to-the-latest-cjeu-judgement-1555813/); [Goodwin via Mondaq](https://www.mondaq.com/uk/data-protection/1683956/personal-data-or-not-cjeu-weighs-in-on-pseudonymisation-in-edps-v-srb)
- EDPB Guidelines 01/2025 on pseudonymisation: v1, consultation closed 14 March 2025; I found no final version. — [EDPB consultation](https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en)
- The Council mandate reportedly keeps Art. 4(1) unchanged, adds Art. 25a under which pseudonymised data is not personal for a third party who cannot identify the person, and states it always remains personal for a processor. Not law. — [EU Internet Policy](https://euinternetpolicy.wordpress.com/2026/10/23/the-councils-digital-omnibus-mandate-what-it-would-change-in-the-gdpr/)
- WP224: safeguards must prevent secondary use of fingerprint data in server security logs. — [WP224](https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2014/wp224_en.pdf)
- GDPR duties to tell admins about (statutory text cited from memory, URLs not re-read this session): [Art. 13 transparency](https://gdpr-info.eu/art-13-gdpr/), [Art. 21 objection](https://gdpr-info.eu/art-21-gdpr/), [Art. 25 by design](https://gdpr-info.eu/art-25-gdpr/), [Art. 28 processors](https://gdpr-info.eu/art-28-gdpr/), [Art. 30 records](https://gdpr-info.eu/art-30-gdpr/), [Art. 32 security](https://gdpr-info.eu/art-32-gdpr/), [Art. 35 DPIA](https://gdpr-info.eu/art-35-gdpr/). Also [Recital 26](https://gdpr-info.eu/recitals/no-26/) on singling out and pseudonymised data.

### Inferences
- **Why self-hosted hashing does not anonymise.** The SRB relative test favours recipients without means, but a self-hosted operator holds the salt, the logs and often the account or IP data, and the very function of a stored fingerprint is to recognise the same device again. Fingerprint inputs also have low entropy, so a plain hash is brute-forceable against enumerated configurations. The honest word is "pseudonymised".
- **A client-computed verdict sent to the server is still a derivation** (¶44), so "we only send a score" is not a way out of Art. 5(3); it is, however, good minimisation under the GDPR.
- A PoW solution is computed from a server-issued challenge rather than from stored device data, so there is a good argument it is not "information already stored". That argument is mine and untested. It weakens if solve timing, thread count or hardware values are reported.
- **What an admin should be told (admin documentation checklist):**
  1. You are the controller; the software author is not responsible for your compliance. No configuration of the tool makes you "compliant" by itself.
  2. Decide and record a mode per form. Document the Art. 5(3)/§ 25 exemption analysis and LIA for each mode, with a template provided.
  3. Add the tool to your privacy notice and processing records, listing exact signals, purposes, retention, and legal basis. Provide generated text based on the actual configuration.
  4. Assess whether a DPIA is needed, especially if behavioural signals or persistent fingerprints are on.
  5. If you use hosting, a CDN, a WAF or a managed Redis, those are processors or third parties and need Art. 28 contracts; check transfers.
  6. Do not reuse security data for analytics, marketing or account-linking, as this destroys the exemption (WP224, CNIL ¶86).
  7. Do not share reputation or fingerprint data across different controllers without fresh legal analysis.
  8. Provide an accessible alternative path and a contact route for false positives.
  9. Check national law and take your own advice; German, French, Austrian and UK positions differ.
- **Minimisation defaults (engineering recommendations, no regulator prescribes these numbers):**
  - Do not persist raw signals; extract coarse features, evaluate, discard.
  - If a linkage key is truly required, use a keyed HMAC with a server-side key that is per-site and rotated (for example, every 24 hours), so there is no cross-site or long-term linkage. Do not use unsalted hashes.
  - Do not use a global salt across tenants.
  - No IP storage by default: in-memory or short-TTL keyed counters for rate limiting (for example, minutes to hours), with /24 or /56-/64 aggregation where effective. Exclude IP from access logs on these endpoints or truncate them.
  - Keep challenge and token state only until expiry (minutes).
  - Keep aggregate counters only, with no per-visitor analytics.
  - Exclude high-entropy, low-signal reads such as font lists, canvas or audio hashes unless the escalation tier needs them; each signal should be justified in a signal register.
  - No cookies or localStorage in the default mode (storage is a separate Art. 5(3) trigger).
  - No remote fonts, CDN scripts or update pings; these would introduce third-party disclosure of IP.
  - Delete by default and make retention enforced by the data store, rather than by policy text alone.

### Gaps
- I found no regulator-specified retention period for CAPTCHA signals or for IP rate-limit data. The numbers above are engineering judgement.
- No authority has addressed whether a PoW solution is "gaining of access".
- The text of EDPB 01/2025 on hashing was not read.

## Q4. Are claims like "GDPR compliant" or "no consent needed" defensible? Safe wording, and how should "true privacy mode" be defined?

### Takeaway
No: neither is defensible as an unconditional product claim. Compliance depends on how the controller deploys the tool, and no court or regulator has endorsed a self-hosted fingerprinting CAPTCHA. Claim only verifiable technical facts, and define "true privacy mode" by what the code does not do, rather than by a legal conclusion.

### Cited Findings
- CNIL advises deployers to verify a provider's terms, placing the assessment on the deployer. — [CNIL FAQ](https://www.cnil.fr/fr/cookies-et-autres-traceurs/regles/cookies/FAQ)
- The EDPB declines to address exemptions, leaving them for case-by-case assessment (¶4), so a general "no consent" claim cannot be attributed to EU-level authority. — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202302_technical_scope_art_53_eprivacydirective_v2_en_0.pdf)
- The exemption is purpose- and deployment-specific and lost on secondary use. — [WP224](https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2014/wp224_en.pdf); [CNIL decision ¶86](https://www.edpb.europa.eu/system/files/2023-08/fr_sa_2023-03-decisionpublic.pdf)
- W3C Note: non-interactive approaches pose no accessibility challenge but may expose personal data, a useful counterweight to "invisible means private". — [W3C Inaccessibility of CAPTCHA](https://www.w3.org/TR/turingtest/)
- **US notes.** California CIPA pen-register suits use a fingerprinting theory after *Greenley v. Kochava* (unpublished, 2023), with over 50 follow-on cases reported and $2,500 per violation. Defendants argue the statute does not reach website operators receiving their own traffic, and one judge sustained a demurrer on IP-only collection. — [K&L Gates](https://www.klgates.com/thought-leadership/Pen-Register-and-Trap-and-Trace-Claims-The-Latest-Wave-of-CIPA-Litigation-3-4-2024); [NatLawReview](https://natlawreview.com/article/new-wave-website-privacy-lawsuits-under-pen-register-and-trap-and-trace-device); [Blank Rome](https://blankrome.com/publications/claim-does-not-pen-register-can-still-carry-punch)

### Inferences

**Claim guidance**

| Avoid | Why | Prefer (only if true for that configuration) |
|---|---|---|
| "GDPR compliant", "DSGVO-konform", "100% compliant" | Compliance attaches to the controller's whole processing | "Designed to support data minimisation. You remain the controller and must assess your own deployment." |
| "No consent needed", "cookie banner not required" | Contested; deployment-specific; contrary to BVwG reasoning | "Default mode sets no cookies and reads no device fingerprint. Whether consent is required for your deployment depends on your configuration and national law; regulators such as CNIL accept consent-free security tools only in narrow conditions." |
| "Anonymous", "no personal data" | IP is personal data in many cases (Breyer); hashes are pseudonymous | "Does not store IP addresses by default. Signals used in [mode] are pseudonymised with a rotating per-site key and deleted after [X]." |
| "Hashed, so not personal data" | DSK Rn. 23; SRB does not help the key holder | "Stored only as keyed, rotating, pseudonymised values." |
| "No tracking" (unqualified) | Overbroad if any linkage exists | "No cross-site identifiers. No sharing with third parties. No reuse for analytics or advertising, in the software as shipped." |
| "Approved by CNIL/DSK/EDPB" | No such approval found | "Our defaults take into account CNIL FAQ Q17 and DSK OH Digitale Dienste. This is not regulator approval." |
| "Fully local", "nothing leaves your browser" | False if any result is sent | "Raw signals stay in the browser; only [named coarse features] are sent to your own server." |
| "Bot-proof", "unforgeable" | See Q5 | "Raises attacker cost; verified on your server." |

Every public statement should be testable by an admin: a published signal register per mode, a network-traffic self-test, and open source for the loader. Also add "This is not legal advice".

**Proposed mode definitions**

- **True privacy mode (strict, the only mode to carry the name).** A hard, testable set of guarantees:
  1. No read of device or browser properties for detection purposes, by script.
  2. No client storage (cookies, localStorage, IndexedDB) beyond ephemeral memory.
  3. No identifiers: neither persistent nor per-device.
  4. No behavioural capture (mouse, keystroke, timing telemetry).
  5. No third-party requests, all assets self-hosted.
  6. The only upload is the PoW solution for a server-issued challenge, plus what HTTP inherently carries.
  7. Server uses IP and headers only transiently for rate limiting and does not persist them. No fingerprint is derived from headers.
  8. Same behaviour regardless of configuration: enforced in code, surfaced in admin UI and in a machine-readable manifest, and any change exits the mode visibly.
  9. Explicitly state the trade-off: this mode raises costs but **does not detect** sophisticated bots or distinguish humans; a well-resourced attacker can pay the PoW.
- **Local-assist mode (must not be called true privacy mode):** browser computes coarse features locally and sends a minimal derived result to the operator. Art. 5(3) applies (EDPB ¶44); exemption reasoning is required; results are forgeable and can only count as weak evidence.
- **Fingerprint-escalation mode:** server-side scoring with fingerprints, on risk trigger only, on protected actions, with pseudonymised short-lived values. The admin must document analysis and notice.

Even in strict mode, say "does not read a device fingerprint", not "outside the ePrivacy Directive". EDPB ¶¶42-43 and ¶55 mean IP handling and transient header use could still be argued to be in scope, and the code delivered to the browser may itself raise storage questions (for example, caching; I did not analyse this point in depth).

### Gaps
- EU/German unfair-competition exposure for false compliance claims (UWG § 5, UCPD) and US FTC Act § 5 deception exposure were not researched in this session, though they are the likely legal basis for "don't over-claim". Have counsel confirm.
- CCPA/CPRA treatment of device identifiers and its security exceptions was searched but not found in results; treat as a gap.
- No regulator-approved sample wording for CAPTCHA was found.

## Q5. Security trust boundary: what can the client be trusted for, and what must be computed on the server?

### Takeaway
Nothing from the client is trustworthy as a statement of fact. The client can be asked to pay costs (PoW, verified on the server), to minimise data before sending it, and to supply weak evidence the server can cross-check. All verdicts, policy, token issuance, and single-use enforcement belong on the server. Obfuscation only buys time, and it conflicts with the auditability a privacy claim needs.

### Cited Findings
- Cloudflare: "The client-side widget alone does not protect your forms", since an attacker can submit any string to your endpoint; server-side validation is mandatory on every submission. Tokens: valid 300 seconds, single use (`timeout-or-duplicate` on replay), up to 2048 characters. Keep the secret in env/key manager, only the backend calls Siteverify, compare `hostname` and `action`, use timeouts and retries, optional `idempotency_key` for safe retries. — [Turnstile validation docs](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
- Token format, RFC 8725 (BCP 225, Feb 2020): pin allowed algorithms and reject others; one algorithm per key; do not accept `none`; validate `iss`; multi-relying-party tokens must have `aud` that is checked; no human-memorable HMAC keys; use explicit `typ` and mutually exclusive validation rules to prevent cross-JWT confusion. It gives no lifetime rules. — [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725)
- PASETO offers versioned protocols rather than algorithm negotiation, with `local` (symmetric AEAD) and `public` (signature) purposes; it "cannot prevent replay attacks alone". The repo page I read showed v2 examples and did not confirm its standards status. — [PASETO spec](https://github.com/paseto-standard/paseto-spec)
- Obfuscation: a 2026 analysis describes Turnstile on ChatGPT as an encrypted VM program (approximately 89 VM instructions wrapping a 19 KB encrypted block) with server-injected checks, and the author reports decrypting it. This shows obfuscation can be reversed, and that server-supplied per-challenge content is the harder part. Single-author, read through a search summary only. — [buchodi analysis (mirror)](https://hn.jakechampion.name/reader/https://www.buchodi.com/chatgpt-wont-let-you-type-until-cloudflare-reads-your-react-state-i-decrypted-the-program-that-does-it/)
- hCaptcha (self-interested) says no single approach is sufficient against sophisticated attacks. Published vendor detection-rate comparisons are unreliable competitor marketing and should not be used. — [hCaptcha blog, seen on an unusual mirror domain, read via search summary](https://hcaptcha.uth.edu/blog/hcaptcha-vs-turnstile); [example vendor claim](https://roundtable.ai/blog/cloudflare-turnstile-reviews-pricing-alternatives)
- W3C on PoW: cost can scale with a client's reputation score, so it should have negligible effect on humans if scoring is accurate; it requires JavaScript and may slow older hardware, without a direct accessibility barrier. Heuristics can be evaded by changing bot footprints. — [W3C Note](https://www.w3.org/TR/turingtest/)
- CSRF/CORS (OWASP): reject cross-site non-safe requests through `Sec-Fetch-Site` with Origin verification as fallback; full-origin comparison; `Origin: null` or missing is not same-origin evidence. CORS alone is not a CSRF defence, and permissive subdomain regexes are unsafe. Signed double-submit should use HMAC with a server secret, session-dependent value and random value, compared in constant time. Client-side code can be tricked into attaching a token to forged requests. — [OWASP CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- CSP (OWASP): strict nonce/hash CSP preferred over allowlists; `object-src 'none'`, `base-uri 'none'`; `frame-ancestors` must be sent as a header and is ignored in `<meta>`; `strict-dynamic` lets trusted scripts load others; inline event handlers are blocked and need `addEventListener`. — [OWASP CSP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- SRI (MDN): cross-origin needs CORS and `crossorigin`; any byte change blocks the load; per-request generated content cannot be pinned; SRI checks integrity, not trustworthiness. `Integrity-Policy` headers can require it. — [MDN SRI](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity)
- Privacy Pass: RFC 9576 (Informational, June 2024) and RFC 9577 (Proposed Standard, June 2024). Roles are client, origin, issuer, attester. Goal is unlinkability, dependent on non-collusion. RFC 9576 acknowledges centralisation pressure and possible discriminatory gating, describes a "low-quality, anti-fraud signal" in one example, and notes hoarding attacks are left to deployments. Origins must prevent double spend where redemption has side effects. — [RFC 9576](https://datatracker.ietf.org/doc/html/rfc9576); [RFC 9577](https://datatracker.ietf.org/doc/html/rfc9577)
- WebAuthn: attestation gives evidence about "the origin of an authenticator", not humanness. Basic attestation shares keys across a model batch. Enterprise attestation may uniquely identify the authenticator and is for controlled deployments. The spec warns of clickjacking in embedded usage and points to Intersection Observer v2's `isVisible`. — [WebAuthn L3](https://www.w3.org/TR/webauthn-3/)
- W3C lists WebAuthn-based attestation of personhood and Privacy Pass among alternatives, warns that deployers of reCAPTCHA v2/v3 expose users to profiling, and concludes there is "no single, ideal solution". — [W3C Note](https://www.w3.org/TR/turingtest/)
- Web Environment Integrity: Chromium prototype existed May-Nov 2023 and was removed after heavy criticism. It proposed attester-signed tokens stating whether the client was authentic. Mozilla opposed it; Brave refused to ship it. The narrower successor is Android WebView Media Integrity API, limited to embedded WebViews. — [Wikipedia](https://en.wikipedia.org/wiki/Web_Environment_Integrity); [OSnews](https://www.osnews.com/story/137723/google-drops-web-environment-integrity-proposal/)

### Inferences

These are design recommendations derived from the above, not sourced facts.

**Trust matrix**

| Concern | Client may | Server must |
|---|---|---|
| Verdict or score | Never decide. Can show UX state only | Compute score from server-held policy; treat client features as untrusted hints |
| PoW | Solve the puzzle | Issue a random signed challenge; set difficulty; verify in O(1); consume once |
| Feature extraction | Reduce raw signals to coarse features (privacy benefit, not security benefit) | Cross-check against headers, TLS or other server-observed data; assume values may be fabricated |
| Timing/behaviour | Report as weak hint, if a non-strict mode | Measure server-side elapsed time between issue and redeem; distrust client clocks |
| Integrity | Obfuscate as optional delay | Rotate challenges, randomise probes, detect impossible combinations, and rely on rate and cost limits |
| Secrets | Hold none: site key is public | Hold HMAC or signing keys, siteverify secret, salts |
| Tokens | Carry opaque tokens | Issue, validate, single-use consume, bind to site, action and origin |

**Why client-only scoring fails:** whoever controls the client can skip the scoring and POST any verdict, and a signing key shipped to the client is public. A client-only mode offers only cosmetic deterrence and must not be described as protection. **Client-only methods that do add value:** PoW (cost imposition, only when verified server-side); local minimisation before sending (a privacy benefit); and honeypots or simple UX friction as weak filters. PoW raises the price rather than proving humanity; botnets and GPU farms discount it, and it hurts low-end devices, so it should be paired with server-side rate limits.

**Challenge and token design**
- Flow: server issues `challenge{id, site, action, origin, difficulty, iat, exp, policy_version, random}` with a MAC or signature, so the server needs no state until redemption, or stores it for stricter control. Client returns solution, optional features. Server verifies MAC, expiry, and binding, atomically marks `id` consumed, computes score, and issues a separate pass token.
- Use different keys and types for challenge and pass tokens to prevent confusion (RFC 8725 §3.12).
- Pass token claims: `jti`, `iss`, `aud` = site, `action`, `hostname`, `iat`, `exp`, key ID, and optionally a coarse outcome band. No raw fingerprints, no IP in clear; tokens pass through logs and browsers. If a claim binding to the IP or a device is needed, use a keyed digest. Note mobile-network IP changes cause false rejections, so treat IP binding as a soft signal.
- **HMAC vs Ed25519 vs PASETO:** use HMAC-SHA-256 with per-site, high-entropy keys if the issuer and verifier are the same service (the normal self-hosted case); it is the simplest. Use Ed25519 if a separate verifier should be able to check tokens without being able to mint them, which suits multi-tenant or embedded verification libraries. Consider PASETO `public` or `local` rather than JWT if you want no algorithm negotiation, or a tiny custom versioned format with a pinned algorithm per version. If using JWT, follow RFC 8725 strictly. Opaque random tokens with server-side lookup are also valid and simplify revocation and data minimisation.
- **Single-use store:** signature alone cannot stop replay (PASETO notes this). Use an atomic check-and-set, for example Redis `SET key NX EX ttl`, with TTL at least the remaining token lifetime plus clock skew. Sized per token expiry. Decide failure behaviour explicitly: fail closed for logins or high-risk actions; configurable degrade for low-risk forms. If siteverify may be retried, use an idempotency key so that a retry after a network failure does not spuriously fail.
- **TTL:** challenge lifetime is minutes; pass token approximately 2-5 minutes, with 300 s as the Turnstile benchmark. Consider a longer TTL for a form the user fills in slowly by solving at submission, not page load, which also serves the Art. 5(3) "protected action" design.
- **Binding checks at siteverify:** verify `aud`/site, `hostname`, `action`, expiry, unused. Return reasons to the backend only. A mismatch on any field is a failure.
- **Siteverify secret handling:** server-to-server only; POST with the secret in a body or header, never in a URL; no CORS on this endpoint; per-site secrets; rotation with two active keys by `kid`; constant-time comparison; redact secrets and tokens from logs; timeouts on the customer's side; rate-limit the endpoint.

**CSRF, CORS and embedding**
- CORS and the `Origin` header limit browsers only; non-browser bots can spoof both, so origin allowlists protect against **site-key misuse by other sites' browsers**, not against bots. Hostname binding still has value for that purpose.
- Challenge endpoints can use tightly allowlisted CORS per site. Token submission to the customer's backend needs that app's normal CSRF defences; a CAPTCHA token is not a CSRF token, and does not bind to a session unless designed to.
- Widget iframe: serving from a dedicated origin isolates state from the host page and from host-page XSS, with `frame-ancestors` per-site. A same-origin inline widget is simpler and needs no frame, but host-page code can tamper with it, which is fine because the client is untrusted anyway. Protect interactive fallback from clickjacking; an overlay can trick a user into solving for another site (token harvesting relay), which origin binding only partly addresses.
- Host CSP: ship no inline scripts, styles or event handlers, and no `eval`/`new Function`, so `script-src 'self'` works. Document exact directives. Support a nonce attribute passed through. Self-hosting on the same origin gives the simplest policy, and no third-party allowance. A JS-interpreter VM can avoid `eval`. WASM PoW and blob-based workers typically need explicit allowances (`wasm-unsafe-eval`, `worker-src`), so provide a plain-file worker URL and JS fallback. (This WASM detail is from my prior knowledge, not re-verified in this session.)
- **SRI vs rotation conflict:** SRI requires stable bytes; a per-request or rotating VM cannot be pinned. Pattern: a small stable, versioned loader with SRI, with rotating challenge content delivered as **data** interpreted by a pinned runtime, or served into an isolated iframe. Self-hosted same-origin deployments reduce the need for SRI, but it remains useful with a separate static host or CDN.

**Obfuscation/VM rotation limits**
- For an open-source, self-hosted project, attackers have the code. Security must follow Kerckhoffs: keys and server policy are the secrets. Rotation can impose repeated analysis cost, but the operator of a small deployment lacks the fleet-wide telemetry of a large vendor, so the benefit is modest and maintenance heavy.
- **Privacy tension:** an opaque, per-request VM that reads unknown signals is at odds with "the admin can verify what the tool reads". The admin is the controller and must describe the processing accurately. Recommend keeping obfuscation **off in true privacy mode**, and in other modes publishing the signal register and the reproducible source of the program generator.

**Attestation options**
- **Private Access Tokens/Privacy Pass:** optional, additive, privacy-preserving signal, and a good fit philosophically since the origin learns little. But it needs an external issuer and attester, which contradicts "no third party" in practice (though the client talks to them, not the origin's server), gives only low-quality evidence and depends on the client's platform; absent tokens must not mean rejection. It must not be enabled in true privacy mode by default without disclosure.
- **WebAuthn attestation:** proves authenticator provenance, not humanity. Requires user gesture; can be correlating; excludes users without a device; farmable. Useful as a step-up for account contexts, with `attestation: none` passkeys as a simple anti-abuse factor, and not as an anonymous visitor check.
- **WEI lesson:** browser or device attestation that gates the open web drew strong opposition. Do not require attested environments; never block open-source browsers or assistive setups by policy.

### Gaps
- No independent, peer-reviewed evaluation of PoW or client-side fingerprinting CAPTCHA robustness was found in this research; other project notes may cover this.
- Current browser support and issuer availability for Private Access Tokens, and whether a self-hosted origin can use them without Cloudflare or Fastly as issuer, were not verified.
- Current PASETO recommended versions and primitives were not confirmed from the page I read (it showed only v2 examples); check paseto.io before specifying them.
- WebAuthn `attestation` conveyance section text was not read in detail.
- The Redis command and failure-behaviour recommendations are engineering judgement.

## Q6. Accessibility law (EAA June 2025, WCAG 2.2 SC 3.3.8) and an accessible alternative path

### Takeaway
The EAA has applied to consumer e-commerce and other listed services since 28 June 2025, so a CAPTCHA blocking checkout, booking or login is a compliance risk for in-scope operators. WCAG 3.3.8 does not ban CAPTCHAs as such and its relevance outside authentication is limited. Invisible PoW with a non-cognitive fallback is the strongest design, and vendor claims of "the law bans CAPTCHA" go too far.

### Cited Findings
- EAA Directive (EU) 2019/882 Art. 2(2): services provided to consumers after 28 June 2025, including e-commerce (Art. 2(2)(f)), defined as services at a distance through websites and mobile device-based services (Art. 3(30)), plus consumer banking, e-books, parts of passenger transport and more. — [Directive 2019/882](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32019L0882)
- Art. 4(5): microenterprises providing services (fewer than 10 employees and at most €2m turnover or balance sheet, Art. 3(23)) are exempt from the accessibility requirements. Art. 14: fundamental-alteration and disproportionate-burden limits, assessed against Annex VI and renewed at least every five years. Art. 15: presumption of conformity with harmonised standards. — [Directive 2019/882](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32019L0882)
- WCAG 2.2 SC 3.3.8 (AA): a cognitive function test "is not required for any step in an authentication process" unless there is an alternative, a mechanism assisting the user, object recognition, or recognition of personal content. Object recognition and personal content exceptions do not carry over to 3.3.9 (AAA). — [W3C Understanding 3.3.8](https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-minimum.html)
- Interpretation dispute: a 2022 W3C mailing-list message proposes reading "authentication" as verifying the user's identity, not whether a user is human. Vendor blogs claiming 3.3.8 bans CAPTCHAs are marketing. — [W3C public-apa 2022](https://lists.w3.org/Archives/Public/public-apa/2022Jan/0002.html); [vendor example](https://www.oopspam.com/blog/captcha-and-accessibility-why-your-forms-might-be-breaking-the-law-in-2026)
- W3C "Inaccessibility of CAPTCHA": the latest published draft found is the Group Draft Note of 16 Dec 2021, updating the 2019 Note. Traditional visual CAPTCHAs are inaccessible for many users, audio CAPTCHAs are poor (cognitive load, cracked by speech recognition), and the WCAG exception is narrow. Non-interactive methods pose no accessibility challenge but may expose personal data. Use the least challenging method necessary, limit interactive challenges, offer multiple alternatives, and monitor. — [W3C Note](https://www.w3.org/TR/turingtest/); [WAI 2019 announcement](https://www.w3.org/WAI/news/2019-08-23/inaccessibility-of-captcha)
- German implementation: BFSG in force since 28 June 2025; technical criteria come through BFSGV and EN 301 549, which points to WCAG 2.1 AA for web content. All secondary vendor sources. — [Baker Tilly](https://www.bakertilly.de/fileadmin/public/Images/Publikationen/BFSG_-_geltende_Anforderungen.pdf); [Xictron](https://www.xictron.com/en/knowledge/wcag-2-1/)
- EN 301 549 v3.2.1 is WCAG 2.1 AA based; v4.1.1 with WCAG 2.2 AA was forecast for OJ citation around Oct 2026 by a vendor, unconfirmed. So 3.3.8 may not yet be part of the presumption-of-conformity baseline. — [EqualWeb](https://www.equalweb.com/platform/standards/en-301549.html)
- Cancellation and withdrawal buttons: a German legal publisher advises checking CAPTCHAs there for cookie-free operation, since § 25 TDDDG could otherwise be triggered. Read through a search summary. — [IT-Recht Kanzlei](https://www.it-recht-kanzlei.de/captcha-kuendigungsbutton-widerrufsbutton.html)

### Inferences
- **Design for WCAG 2.2 AA anyway**, since it is the direction of travel and is cheap for a non-interactive design. Invisible PoW is not a cognitive function test; keep it the default.
- **Accessible alternative path requirements (design proposal):**
  1. Non-cognitive first: PoW and passive server checks; no puzzles by default.
  2. Any interactive escalation must not be the sole route. Offer at least one non-puzzle alternative: an emailed one-time link or code (with paste allowed), a passkey or login for known users, or a human contact route that the operator commits to answering, with an advertised response time.
  3. Works for keyboard and screen reader (labelled status, `aria-live`, no focus traps), respects reduced motion, has no time-limit traps (expired challenges silently refresh), and no audio-only or visual-only challenge. Audio is not a sufficient alternative.
  4. Long PoW must show progress and be cancellable; cap difficulty for accessibility, with fallback when low-end devices would exceed a time budget.
  5. A no-JavaScript route (server-side form with rate limiting or email confirmation), since PoW requires JS (W3C).
  6. Assistive-tech false positives: do not treat unusual input modalities, browser extensions or lack of pointer movement as bot evidence by itself. Avoid behaviour signals that disadvantage switch, voice or screen-reader users. Monitor and allow appeal.
  7. Do not place fingerprint-gated CAPTCHAs on legally mandated flows (cancellation buttons, withdrawal, data subject requests) without an alternative.
  8. The alternative path must itself be abuse-limited: rate-limit it and keep its data handling in the privacy notice.
- **Privacy and accessibility must be tested together:** an email fallback collects personal data, while no-JS may need more server state. The true privacy mode should document the fallback's data handling.

### Gaps
- No official Bundesfachstelle or market surveillance statement specifically about CAPTCHA was found. No EAA enforcement case on CAPTCHA was found.
- EN 301 549 v4.1.1 publication and OJ citation status could not be confirmed. Check ETSI and the OJ.
- Art. 32 EAA transition details were not read (truncated in fetch). Whether WCAG 3.3.8 has been interpreted officially beyond the Understanding document for "human check" flows remains unresolved.
- US accessibility exposure (ADA Title III web litigation) was not researched.
