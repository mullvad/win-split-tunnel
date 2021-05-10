#pragma once

#include <initguid.h>

///////////////////////////////////////////////////////////////////////////////
//
// Identifiers used with WFP.
//
///////////////////////////////////////////////////////////////////////////////

// {E2C114EE-F32A-4264-A6CB-3FA7996356D9}
DEFINE_GUID(ST_FW_PROVIDER_KEY,
	0xe2c114ee, 0xf32a, 0x4264, 0xa6, 0xcb, 0x3f, 0xa7, 0x99, 0x63, 0x56, 0xd9);

// {76653805-1972-45D1-B47C-3140AEBABC49}
DEFINE_GUID(ST_FW_CALLOUT_CLASSIFY_BIND_IPV4_KEY,
	0x76653805, 0x1972, 0x45d1, 0xb4, 0x7c, 0x31, 0x40, 0xae, 0xba, 0xbc, 0x49);

// {53FB3120-B6A4-462B-BFFC-6978AADA1DA2}
DEFINE_GUID(ST_FW_CALLOUT_CLASSIFY_BIND_IPV6_KEY,
	0x53fb3120, 0xb6a4, 0x462b, 0xbf, 0xfc, 0x69, 0x78, 0xaa, 0xda, 0x1d, 0xa2);

// {A4E010B5-DC3F-474A-B7C2-2F3269945F41}
DEFINE_GUID(ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV4_KEY,
	0xa4e010b5, 0xdc3f, 0x474a, 0xb7, 0xc2, 0x2f, 0x32, 0x69, 0x94, 0x5f, 0x41);

// {6B634022-B3D3-4667-88BA-BF5028858F52}
DEFINE_GUID(ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV6_KEY,
	0x6b634022, 0xb3d3, 0x4667, 0x88, 0xba, 0xbf, 0x50, 0x28, 0x85, 0x8f, 0x52);

// {33F3EDCC-EB5E-41CF-9250-702C94A28E39}
DEFINE_GUID(ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_CONN_KEY,
	0x33f3edcc, 0xeb5e, 0x41cf, 0x92, 0x50, 0x70, 0x2c, 0x94, 0xa2, 0x8e, 0x39);

// {A7A13809-0DE6-48AB-9BB8-20A8BCEC37AB}
DEFINE_GUID(ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_RECV_KEY,
	0xa7a13809, 0xde6, 0x48ab, 0x9b, 0xb8, 0x20, 0xa8, 0xbc, 0xec, 0x37, 0xab);

// {7B7E0055-89F5-4760-8928-CCD57C8830AB}
DEFINE_GUID(ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_CONN_KEY,
	0x7b7e0055, 0x89f5, 0x4760, 0x89, 0x28, 0xcc, 0xd5, 0x7c, 0x88, 0x30, 0xab);

// {B40B78EF-5642-40EF-AC4D-F9651261F9E7}
DEFINE_GUID(ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_RECV_KEY,
	0xb40b78ef, 0x5642, 0x40ef, 0xac, 0x4d, 0xf9, 0x65, 0x12, 0x61, 0xf9, 0xe7);

// {974AA588-397A-483E-AC29-88F4F4112AC2}
DEFINE_GUID(ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_CONN_KEY,
	0x974aa588, 0x397a, 0x483e, 0xac, 0x29, 0x88, 0xf4, 0xf4, 0x11, 0x2a, 0xc2);

// {8E314FD7-BDD3-45A4-A712-46036B25B3E1}
DEFINE_GUID(ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_RECV_KEY,
	0x8e314fd7, 0xbdd3, 0x45a4, 0xa7, 0x12, 0x46, 0x3, 0x6b, 0x25, 0xb3, 0xe1);

// {466B7800-5EF4-4772-AA79-E0A834328214}
DEFINE_GUID(ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_CONN_KEY,
	0x466b7800, 0x5ef4, 0x4772, 0xaa, 0x79, 0xe0, 0xa8, 0x34, 0x32, 0x82, 0x14);

// {D25AFB1B-4645-43CB-B0BE-3794FE487BAC}
DEFINE_GUID(ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_RECV_KEY,
	0xd25afb1b, 0x4645, 0x43cb, 0xb0, 0xbe, 0x37, 0x94, 0xfe, 0x48, 0x7b, 0xac);

// {B47D14A7-AEED-48B9-AD4E-5529619F1337}
DEFINE_GUID(ST_FW_FILTER_CLASSIFY_BIND_IPV4_KEY,
	0xb47d14a7, 0xaeed, 0x48b9, 0xad, 0x4e, 0x55, 0x29, 0x61, 0x9f, 0x13, 0x37);

// {2F607222-B2EB-443C-B6E0-641067375478}
DEFINE_GUID(ST_FW_FILTER_CLASSIFY_BIND_IPV6_KEY,
	0x2f607222, 0xb2eb, 0x443c, 0xb6, 0xe0, 0x64, 0x10, 0x67, 0x37, 0x54, 0x78);

// {4207F127-CC80-477E-ADDF-26F76585E073}
DEFINE_GUID(ST_FW_FILTER_CLASSIFY_CONNECT_IPV4_KEY,
	0x4207f127, 0xcc80, 0x477e, 0xad, 0xdf, 0x26, 0xf7, 0x65, 0x85, 0xe0, 0x73);

// {9A87F137-5112-4427-B315-4F87B3E84DCC}
DEFINE_GUID(ST_FW_FILTER_CLASSIFY_CONNECT_IPV6_KEY,
	0x9a87f137, 0x5112, 0x4427, 0xb3, 0x15, 0x4f, 0x87, 0xb3, 0xe8, 0x4d, 0xcc);

// {66CED079-C270-4B4D-A45C-D11711C0D600}
DEFINE_GUID(ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_CONN_KEY,
	0x66ced079, 0xc270, 0x4b4d, 0xa4, 0x5c, 0xd1, 0x17, 0x11, 0xc0, 0xd6, 0x0);

// {37972155-EBDB-49FC-9A37-3A0B3B0AA100}
DEFINE_GUID(ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_RECV_KEY,
	0x37972155, 0xebdb, 0x49fc, 0x9a, 0x37, 0x3a, 0xb, 0x3b, 0xa, 0xa1, 0x0);

// {0AFA08E3-B010-4082-9E03-1CC4BE1C6CF8}
DEFINE_GUID(ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_CONN_KEY,
	0xafa08e3, 0xb010, 0x4082, 0x9e, 0x3, 0x1c, 0xc4, 0xbe, 0x1c, 0x6c, 0xf8);

// {7835DFD7-24AE-44F4-8A8A-5E9C766AAE63}
DEFINE_GUID(ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_RECV_KEY,
	0x7835dfd7, 0x24ae, 0x44f4, 0x8a, 0x8a, 0x5e, 0x9c, 0x76, 0x6a, 0xae, 0x63);

// {D8602FF5-436B-414A-A221-7B4DE8CE96C7}
DEFINE_GUID(ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_TUNNEL_IPV4_CONN_KEY,
	0xd8602ff5, 0x436b, 0x414a, 0xa2, 0x21, 0x7b, 0x4d, 0xe8, 0xce, 0x96, 0xc7);

// {FC3F8D71-33F7-4D24-9306-A3DEE3F7C865}
DEFINE_GUID(ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_TUNNEL_IPV4_RECV_KEY,
	0xfc3f8d71, 0x33f7, 0x4d24, 0x93, 0x6, 0xa3, 0xde, 0xe3, 0xf7, 0xc8, 0x65);

// {05CB3C5E-6F64-44F7-81B1-C890563FA280}
DEFINE_GUID(ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_TUNNEL_IPV6_CONN_KEY,
	0x5cb3c5e, 0x6f64, 0x44f7, 0x81, 0xb1, 0xc8, 0x90, 0x56, 0x3f, 0xa2, 0x80);

// {C854E73A-81C8-4814-9A55-55BAF2C3BD17}
DEFINE_GUID(ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_TUNNEL_IPV6_RECV_KEY,
	0xc854e73a, 0x81c8, 0x4814, 0x9a, 0x55, 0x55, 0xba, 0xf2, 0xc3, 0xbd, 0x17);

//
// This sublayer is defined and registered by `winfw`.
// We're going to reuse it to avoid having different sublayers fight over
// whether something should be blocked or permitted.
//
DEFINE_GUID(ST_FW_WINFW_BASELINE_SUBLAYER_KEY,
	0xc78056ff, 0x2bc1, 0x4211, 0xaa, 0xdd, 0x7f, 0x35, 0x8d, 0xef, 0x20, 0x2d);

// {FDC95593-04EF-415C-AE68-46BD8B4821A8}
DEFINE_GUID(ST_FW_PROVIDER_CONTEXT_KEY,
	0xfdc95593, 0x4ef, 0x415c, 0xae, 0x68, 0x46, 0xbd, 0x8b, 0x48, 0x21, 0xa8);
