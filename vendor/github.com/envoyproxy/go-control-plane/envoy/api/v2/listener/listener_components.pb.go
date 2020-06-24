// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/api/v2/listener/listener_components.proto

package envoy_api_v2_listener

import (
	fmt "fmt"
	_ "github.com/cncf/udpa/go/udpa/annotations"
	auth "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	_type "github.com/envoyproxy/go-control-plane/envoy/type"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	any "github.com/golang/protobuf/ptypes/any"
	_struct "github.com/golang/protobuf/ptypes/struct"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type FilterChainMatch_ConnectionSourceType int32

const (
	FilterChainMatch_ANY      FilterChainMatch_ConnectionSourceType = 0
	FilterChainMatch_LOCAL    FilterChainMatch_ConnectionSourceType = 1
	FilterChainMatch_EXTERNAL FilterChainMatch_ConnectionSourceType = 2
)

var FilterChainMatch_ConnectionSourceType_name = map[int32]string{
	0: "ANY",
	1: "LOCAL",
	2: "EXTERNAL",
}

var FilterChainMatch_ConnectionSourceType_value = map[string]int32{
	"ANY":      0,
	"LOCAL":    1,
	"EXTERNAL": 2,
}

func (x FilterChainMatch_ConnectionSourceType) String() string {
	return proto.EnumName(FilterChainMatch_ConnectionSourceType_name, int32(x))
}

func (FilterChainMatch_ConnectionSourceType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_30285372e511ffb4, []int{1, 0}
}

type Filter struct {
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Types that are valid to be assigned to ConfigType:
	//	*Filter_Config
	//	*Filter_TypedConfig
	ConfigType           isFilter_ConfigType `protobuf_oneof:"config_type"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *Filter) Reset()         { *m = Filter{} }
func (m *Filter) String() string { return proto.CompactTextString(m) }
func (*Filter) ProtoMessage()    {}
func (*Filter) Descriptor() ([]byte, []int) {
	return fileDescriptor_30285372e511ffb4, []int{0}
}

func (m *Filter) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Filter.Unmarshal(m, b)
}
func (m *Filter) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Filter.Marshal(b, m, deterministic)
}
func (m *Filter) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Filter.Merge(m, src)
}
func (m *Filter) XXX_Size() int {
	return xxx_messageInfo_Filter.Size(m)
}
func (m *Filter) XXX_DiscardUnknown() {
	xxx_messageInfo_Filter.DiscardUnknown(m)
}

var xxx_messageInfo_Filter proto.InternalMessageInfo

func (m *Filter) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type isFilter_ConfigType interface {
	isFilter_ConfigType()
}

type Filter_Config struct {
	Config *_struct.Struct `protobuf:"bytes,2,opt,name=config,proto3,oneof"`
}

type Filter_TypedConfig struct {
	TypedConfig *any.Any `protobuf:"bytes,4,opt,name=typed_config,json=typedConfig,proto3,oneof"`
}

func (*Filter_Config) isFilter_ConfigType() {}

func (*Filter_TypedConfig) isFilter_ConfigType() {}

func (m *Filter) GetConfigType() isFilter_ConfigType {
	if m != nil {
		return m.ConfigType
	}
	return nil
}

// Deprecated: Do not use.
func (m *Filter) GetConfig() *_struct.Struct {
	if x, ok := m.GetConfigType().(*Filter_Config); ok {
		return x.Config
	}
	return nil
}

func (m *Filter) GetTypedConfig() *any.Any {
	if x, ok := m.GetConfigType().(*Filter_TypedConfig); ok {
		return x.TypedConfig
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*Filter) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*Filter_Config)(nil),
		(*Filter_TypedConfig)(nil),
	}
}

type FilterChainMatch struct {
	DestinationPort      *wrappers.UInt32Value                 `protobuf:"bytes,8,opt,name=destination_port,json=destinationPort,proto3" json:"destination_port,omitempty"`
	PrefixRanges         []*core.CidrRange                     `protobuf:"bytes,3,rep,name=prefix_ranges,json=prefixRanges,proto3" json:"prefix_ranges,omitempty"`
	AddressSuffix        string                                `protobuf:"bytes,4,opt,name=address_suffix,json=addressSuffix,proto3" json:"address_suffix,omitempty"`
	SuffixLen            *wrappers.UInt32Value                 `protobuf:"bytes,5,opt,name=suffix_len,json=suffixLen,proto3" json:"suffix_len,omitempty"`
	SourceType           FilterChainMatch_ConnectionSourceType `protobuf:"varint,12,opt,name=source_type,json=sourceType,proto3,enum=envoy.api.v2.listener.FilterChainMatch_ConnectionSourceType" json:"source_type,omitempty"`
	SourcePrefixRanges   []*core.CidrRange                     `protobuf:"bytes,6,rep,name=source_prefix_ranges,json=sourcePrefixRanges,proto3" json:"source_prefix_ranges,omitempty"`
	SourcePorts          []uint32                              `protobuf:"varint,7,rep,packed,name=source_ports,json=sourcePorts,proto3" json:"source_ports,omitempty"`
	ServerNames          []string                              `protobuf:"bytes,11,rep,name=server_names,json=serverNames,proto3" json:"server_names,omitempty"`
	TransportProtocol    string                                `protobuf:"bytes,9,opt,name=transport_protocol,json=transportProtocol,proto3" json:"transport_protocol,omitempty"`
	ApplicationProtocols []string                              `protobuf:"bytes,10,rep,name=application_protocols,json=applicationProtocols,proto3" json:"application_protocols,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                              `json:"-"`
	XXX_unrecognized     []byte                                `json:"-"`
	XXX_sizecache        int32                                 `json:"-"`
}

func (m *FilterChainMatch) Reset()         { *m = FilterChainMatch{} }
func (m *FilterChainMatch) String() string { return proto.CompactTextString(m) }
func (*FilterChainMatch) ProtoMessage()    {}
func (*FilterChainMatch) Descriptor() ([]byte, []int) {
	return fileDescriptor_30285372e511ffb4, []int{1}
}

func (m *FilterChainMatch) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FilterChainMatch.Unmarshal(m, b)
}
func (m *FilterChainMatch) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FilterChainMatch.Marshal(b, m, deterministic)
}
func (m *FilterChainMatch) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FilterChainMatch.Merge(m, src)
}
func (m *FilterChainMatch) XXX_Size() int {
	return xxx_messageInfo_FilterChainMatch.Size(m)
}
func (m *FilterChainMatch) XXX_DiscardUnknown() {
	xxx_messageInfo_FilterChainMatch.DiscardUnknown(m)
}

var xxx_messageInfo_FilterChainMatch proto.InternalMessageInfo

func (m *FilterChainMatch) GetDestinationPort() *wrappers.UInt32Value {
	if m != nil {
		return m.DestinationPort
	}
	return nil
}

func (m *FilterChainMatch) GetPrefixRanges() []*core.CidrRange {
	if m != nil {
		return m.PrefixRanges
	}
	return nil
}

func (m *FilterChainMatch) GetAddressSuffix() string {
	if m != nil {
		return m.AddressSuffix
	}
	return ""
}

func (m *FilterChainMatch) GetSuffixLen() *wrappers.UInt32Value {
	if m != nil {
		return m.SuffixLen
	}
	return nil
}

func (m *FilterChainMatch) GetSourceType() FilterChainMatch_ConnectionSourceType {
	if m != nil {
		return m.SourceType
	}
	return FilterChainMatch_ANY
}

func (m *FilterChainMatch) GetSourcePrefixRanges() []*core.CidrRange {
	if m != nil {
		return m.SourcePrefixRanges
	}
	return nil
}

func (m *FilterChainMatch) GetSourcePorts() []uint32 {
	if m != nil {
		return m.SourcePorts
	}
	return nil
}

func (m *FilterChainMatch) GetServerNames() []string {
	if m != nil {
		return m.ServerNames
	}
	return nil
}

func (m *FilterChainMatch) GetTransportProtocol() string {
	if m != nil {
		return m.TransportProtocol
	}
	return ""
}

func (m *FilterChainMatch) GetApplicationProtocols() []string {
	if m != nil {
		return m.ApplicationProtocols
	}
	return nil
}

type FilterChain struct {
	FilterChainMatch     *FilterChainMatch          `protobuf:"bytes,1,opt,name=filter_chain_match,json=filterChainMatch,proto3" json:"filter_chain_match,omitempty"`
	TlsContext           *auth.DownstreamTlsContext `protobuf:"bytes,2,opt,name=tls_context,json=tlsContext,proto3" json:"tls_context,omitempty"` // Deprecated: Do not use.
	Filters              []*Filter                  `protobuf:"bytes,3,rep,name=filters,proto3" json:"filters,omitempty"`
	UseProxyProto        *wrappers.BoolValue        `protobuf:"bytes,4,opt,name=use_proxy_proto,json=useProxyProto,proto3" json:"use_proxy_proto,omitempty"`
	Metadata             *core.Metadata             `protobuf:"bytes,5,opt,name=metadata,proto3" json:"metadata,omitempty"`
	TransportSocket      *core.TransportSocket      `protobuf:"bytes,6,opt,name=transport_socket,json=transportSocket,proto3" json:"transport_socket,omitempty"`
	Name                 string                     `protobuf:"bytes,7,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-"`
	XXX_unrecognized     []byte                     `json:"-"`
	XXX_sizecache        int32                      `json:"-"`
}

func (m *FilterChain) Reset()         { *m = FilterChain{} }
func (m *FilterChain) String() string { return proto.CompactTextString(m) }
func (*FilterChain) ProtoMessage()    {}
func (*FilterChain) Descriptor() ([]byte, []int) {
	return fileDescriptor_30285372e511ffb4, []int{2}
}

func (m *FilterChain) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FilterChain.Unmarshal(m, b)
}
func (m *FilterChain) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FilterChain.Marshal(b, m, deterministic)
}
func (m *FilterChain) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FilterChain.Merge(m, src)
}
func (m *FilterChain) XXX_Size() int {
	return xxx_messageInfo_FilterChain.Size(m)
}
func (m *FilterChain) XXX_DiscardUnknown() {
	xxx_messageInfo_FilterChain.DiscardUnknown(m)
}

var xxx_messageInfo_FilterChain proto.InternalMessageInfo

func (m *FilterChain) GetFilterChainMatch() *FilterChainMatch {
	if m != nil {
		return m.FilterChainMatch
	}
	return nil
}

// Deprecated: Do not use.
func (m *FilterChain) GetTlsContext() *auth.DownstreamTlsContext {
	if m != nil {
		return m.TlsContext
	}
	return nil
}

func (m *FilterChain) GetFilters() []*Filter {
	if m != nil {
		return m.Filters
	}
	return nil
}

func (m *FilterChain) GetUseProxyProto() *wrappers.BoolValue {
	if m != nil {
		return m.UseProxyProto
	}
	return nil
}

func (m *FilterChain) GetMetadata() *core.Metadata {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *FilterChain) GetTransportSocket() *core.TransportSocket {
	if m != nil {
		return m.TransportSocket
	}
	return nil
}

func (m *FilterChain) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type ListenerFilterChainMatchPredicate struct {
	// Types that are valid to be assigned to Rule:
	//	*ListenerFilterChainMatchPredicate_OrMatch
	//	*ListenerFilterChainMatchPredicate_AndMatch
	//	*ListenerFilterChainMatchPredicate_NotMatch
	//	*ListenerFilterChainMatchPredicate_AnyMatch
	//	*ListenerFilterChainMatchPredicate_DestinationPortRange
	Rule                 isListenerFilterChainMatchPredicate_Rule `protobuf_oneof:"rule"`
	XXX_NoUnkeyedLiteral struct{}                                 `json:"-"`
	XXX_unrecognized     []byte                                   `json:"-"`
	XXX_sizecache        int32                                    `json:"-"`
}

func (m *ListenerFilterChainMatchPredicate) Reset()         { *m = ListenerFilterChainMatchPredicate{} }
func (m *ListenerFilterChainMatchPredicate) String() string { return proto.CompactTextString(m) }
func (*ListenerFilterChainMatchPredicate) ProtoMessage()    {}
func (*ListenerFilterChainMatchPredicate) Descriptor() ([]byte, []int) {
	return fileDescriptor_30285372e511ffb4, []int{3}
}

func (m *ListenerFilterChainMatchPredicate) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListenerFilterChainMatchPredicate.Unmarshal(m, b)
}
func (m *ListenerFilterChainMatchPredicate) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListenerFilterChainMatchPredicate.Marshal(b, m, deterministic)
}
func (m *ListenerFilterChainMatchPredicate) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListenerFilterChainMatchPredicate.Merge(m, src)
}
func (m *ListenerFilterChainMatchPredicate) XXX_Size() int {
	return xxx_messageInfo_ListenerFilterChainMatchPredicate.Size(m)
}
func (m *ListenerFilterChainMatchPredicate) XXX_DiscardUnknown() {
	xxx_messageInfo_ListenerFilterChainMatchPredicate.DiscardUnknown(m)
}

var xxx_messageInfo_ListenerFilterChainMatchPredicate proto.InternalMessageInfo

type isListenerFilterChainMatchPredicate_Rule interface {
	isListenerFilterChainMatchPredicate_Rule()
}

type ListenerFilterChainMatchPredicate_OrMatch struct {
	OrMatch *ListenerFilterChainMatchPredicate_MatchSet `protobuf:"bytes,1,opt,name=or_match,json=orMatch,proto3,oneof"`
}

type ListenerFilterChainMatchPredicate_AndMatch struct {
	AndMatch *ListenerFilterChainMatchPredicate_MatchSet `protobuf:"bytes,2,opt,name=and_match,json=andMatch,proto3,oneof"`
}

type ListenerFilterChainMatchPredicate_NotMatch struct {
	NotMatch *ListenerFilterChainMatchPredicate `protobuf:"bytes,3,opt,name=not_match,json=notMatch,proto3,oneof"`
}

type ListenerFilterChainMatchPredicate_AnyMatch struct {
	AnyMatch bool `protobuf:"varint,4,opt,name=any_match,json=anyMatch,proto3,oneof"`
}

type ListenerFilterChainMatchPredicate_DestinationPortRange struct {
	DestinationPortRange *_type.Int32Range `protobuf:"bytes,5,opt,name=destination_port_range,json=destinationPortRange,proto3,oneof"`
}

func (*ListenerFilterChainMatchPredicate_OrMatch) isListenerFilterChainMatchPredicate_Rule() {}

func (*ListenerFilterChainMatchPredicate_AndMatch) isListenerFilterChainMatchPredicate_Rule() {}

func (*ListenerFilterChainMatchPredicate_NotMatch) isListenerFilterChainMatchPredicate_Rule() {}

func (*ListenerFilterChainMatchPredicate_AnyMatch) isListenerFilterChainMatchPredicate_Rule() {}

func (*ListenerFilterChainMatchPredicate_DestinationPortRange) isListenerFilterChainMatchPredicate_Rule() {
}

func (m *ListenerFilterChainMatchPredicate) GetRule() isListenerFilterChainMatchPredicate_Rule {
	if m != nil {
		return m.Rule
	}
	return nil
}

func (m *ListenerFilterChainMatchPredicate) GetOrMatch() *ListenerFilterChainMatchPredicate_MatchSet {
	if x, ok := m.GetRule().(*ListenerFilterChainMatchPredicate_OrMatch); ok {
		return x.OrMatch
	}
	return nil
}

func (m *ListenerFilterChainMatchPredicate) GetAndMatch() *ListenerFilterChainMatchPredicate_MatchSet {
	if x, ok := m.GetRule().(*ListenerFilterChainMatchPredicate_AndMatch); ok {
		return x.AndMatch
	}
	return nil
}

func (m *ListenerFilterChainMatchPredicate) GetNotMatch() *ListenerFilterChainMatchPredicate {
	if x, ok := m.GetRule().(*ListenerFilterChainMatchPredicate_NotMatch); ok {
		return x.NotMatch
	}
	return nil
}

func (m *ListenerFilterChainMatchPredicate) GetAnyMatch() bool {
	if x, ok := m.GetRule().(*ListenerFilterChainMatchPredicate_AnyMatch); ok {
		return x.AnyMatch
	}
	return false
}

func (m *ListenerFilterChainMatchPredicate) GetDestinationPortRange() *_type.Int32Range {
	if x, ok := m.GetRule().(*ListenerFilterChainMatchPredicate_DestinationPortRange); ok {
		return x.DestinationPortRange
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*ListenerFilterChainMatchPredicate) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*ListenerFilterChainMatchPredicate_OrMatch)(nil),
		(*ListenerFilterChainMatchPredicate_AndMatch)(nil),
		(*ListenerFilterChainMatchPredicate_NotMatch)(nil),
		(*ListenerFilterChainMatchPredicate_AnyMatch)(nil),
		(*ListenerFilterChainMatchPredicate_DestinationPortRange)(nil),
	}
}

type ListenerFilterChainMatchPredicate_MatchSet struct {
	Rules                []*ListenerFilterChainMatchPredicate `protobuf:"bytes,1,rep,name=rules,proto3" json:"rules,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                             `json:"-"`
	XXX_unrecognized     []byte                               `json:"-"`
	XXX_sizecache        int32                                `json:"-"`
}

func (m *ListenerFilterChainMatchPredicate_MatchSet) Reset() {
	*m = ListenerFilterChainMatchPredicate_MatchSet{}
}
func (m *ListenerFilterChainMatchPredicate_MatchSet) String() string {
	return proto.CompactTextString(m)
}
func (*ListenerFilterChainMatchPredicate_MatchSet) ProtoMessage() {}
func (*ListenerFilterChainMatchPredicate_MatchSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_30285372e511ffb4, []int{3, 0}
}

func (m *ListenerFilterChainMatchPredicate_MatchSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListenerFilterChainMatchPredicate_MatchSet.Unmarshal(m, b)
}
func (m *ListenerFilterChainMatchPredicate_MatchSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListenerFilterChainMatchPredicate_MatchSet.Marshal(b, m, deterministic)
}
func (m *ListenerFilterChainMatchPredicate_MatchSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListenerFilterChainMatchPredicate_MatchSet.Merge(m, src)
}
func (m *ListenerFilterChainMatchPredicate_MatchSet) XXX_Size() int {
	return xxx_messageInfo_ListenerFilterChainMatchPredicate_MatchSet.Size(m)
}
func (m *ListenerFilterChainMatchPredicate_MatchSet) XXX_DiscardUnknown() {
	xxx_messageInfo_ListenerFilterChainMatchPredicate_MatchSet.DiscardUnknown(m)
}

var xxx_messageInfo_ListenerFilterChainMatchPredicate_MatchSet proto.InternalMessageInfo

func (m *ListenerFilterChainMatchPredicate_MatchSet) GetRules() []*ListenerFilterChainMatchPredicate {
	if m != nil {
		return m.Rules
	}
	return nil
}

type ListenerFilter struct {
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Types that are valid to be assigned to ConfigType:
	//	*ListenerFilter_Config
	//	*ListenerFilter_TypedConfig
	ConfigType           isListenerFilter_ConfigType        `protobuf_oneof:"config_type"`
	FilterDisabled       *ListenerFilterChainMatchPredicate `protobuf:"bytes,4,opt,name=filter_disabled,json=filterDisabled,proto3" json:"filter_disabled,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                           `json:"-"`
	XXX_unrecognized     []byte                             `json:"-"`
	XXX_sizecache        int32                              `json:"-"`
}

func (m *ListenerFilter) Reset()         { *m = ListenerFilter{} }
func (m *ListenerFilter) String() string { return proto.CompactTextString(m) }
func (*ListenerFilter) ProtoMessage()    {}
func (*ListenerFilter) Descriptor() ([]byte, []int) {
	return fileDescriptor_30285372e511ffb4, []int{4}
}

func (m *ListenerFilter) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListenerFilter.Unmarshal(m, b)
}
func (m *ListenerFilter) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListenerFilter.Marshal(b, m, deterministic)
}
func (m *ListenerFilter) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListenerFilter.Merge(m, src)
}
func (m *ListenerFilter) XXX_Size() int {
	return xxx_messageInfo_ListenerFilter.Size(m)
}
func (m *ListenerFilter) XXX_DiscardUnknown() {
	xxx_messageInfo_ListenerFilter.DiscardUnknown(m)
}

var xxx_messageInfo_ListenerFilter proto.InternalMessageInfo

func (m *ListenerFilter) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type isListenerFilter_ConfigType interface {
	isListenerFilter_ConfigType()
}

type ListenerFilter_Config struct {
	Config *_struct.Struct `protobuf:"bytes,2,opt,name=config,proto3,oneof"`
}

type ListenerFilter_TypedConfig struct {
	TypedConfig *any.Any `protobuf:"bytes,3,opt,name=typed_config,json=typedConfig,proto3,oneof"`
}

func (*ListenerFilter_Config) isListenerFilter_ConfigType() {}

func (*ListenerFilter_TypedConfig) isListenerFilter_ConfigType() {}

func (m *ListenerFilter) GetConfigType() isListenerFilter_ConfigType {
	if m != nil {
		return m.ConfigType
	}
	return nil
}

// Deprecated: Do not use.
func (m *ListenerFilter) GetConfig() *_struct.Struct {
	if x, ok := m.GetConfigType().(*ListenerFilter_Config); ok {
		return x.Config
	}
	return nil
}

func (m *ListenerFilter) GetTypedConfig() *any.Any {
	if x, ok := m.GetConfigType().(*ListenerFilter_TypedConfig); ok {
		return x.TypedConfig
	}
	return nil
}

func (m *ListenerFilter) GetFilterDisabled() *ListenerFilterChainMatchPredicate {
	if m != nil {
		return m.FilterDisabled
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*ListenerFilter) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*ListenerFilter_Config)(nil),
		(*ListenerFilter_TypedConfig)(nil),
	}
}

func init() {
	proto.RegisterEnum("envoy.api.v2.listener.FilterChainMatch_ConnectionSourceType", FilterChainMatch_ConnectionSourceType_name, FilterChainMatch_ConnectionSourceType_value)
	proto.RegisterType((*Filter)(nil), "envoy.api.v2.listener.Filter")
	proto.RegisterType((*FilterChainMatch)(nil), "envoy.api.v2.listener.FilterChainMatch")
	proto.RegisterType((*FilterChain)(nil), "envoy.api.v2.listener.FilterChain")
	proto.RegisterType((*ListenerFilterChainMatchPredicate)(nil), "envoy.api.v2.listener.ListenerFilterChainMatchPredicate")
	proto.RegisterType((*ListenerFilterChainMatchPredicate_MatchSet)(nil), "envoy.api.v2.listener.ListenerFilterChainMatchPredicate.MatchSet")
	proto.RegisterType((*ListenerFilter)(nil), "envoy.api.v2.listener.ListenerFilter")
}

func init() {
	proto.RegisterFile("envoy/api/v2/listener/listener_components.proto", fileDescriptor_30285372e511ffb4)
}

var fileDescriptor_30285372e511ffb4 = []byte{
	// 1154 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x56, 0x4f, 0x6f, 0x1b, 0x45,
	0x14, 0xcf, 0xae, 0x1d, 0x67, 0x3d, 0xce, 0x9f, 0x65, 0x48, 0x9b, 0x25, 0xfd, 0x83, 0x6b, 0x44,
	0x89, 0x90, 0xd8, 0x95, 0x1c, 0xa1, 0x82, 0xe0, 0xe2, 0x75, 0x83, 0xd2, 0xe2, 0x38, 0xd6, 0x3a,
	0x2d, 0xe5, 0xc2, 0x32, 0xd9, 0x1d, 0xbb, 0x0b, 0xeb, 0x99, 0xd5, 0xcc, 0xd8, 0x8d, 0x6f, 0x88,
	0x2f, 0x80, 0xe8, 0x89, 0x03, 0x5f, 0x00, 0xc4, 0x27, 0xe0, 0x13, 0x20, 0x71, 0xe2, 0x23, 0x70,
	0xe5, 0xc8, 0x09, 0xe5, 0x40, 0xd1, 0xce, 0xcc, 0xba, 0xb1, 0x93, 0xd2, 0xaa, 0x42, 0xdc, 0x76,
	0xde, 0x9f, 0xdf, 0x7b, 0xf3, 0xde, 0xef, 0xbd, 0x59, 0xe0, 0x61, 0x32, 0xa1, 0x53, 0x0f, 0x65,
	0x89, 0x37, 0x69, 0x7a, 0x69, 0xc2, 0x05, 0x26, 0x98, 0xcd, 0x3e, 0xc2, 0x88, 0x8e, 0x32, 0x4a,
	0x30, 0x11, 0xdc, 0xcd, 0x18, 0x15, 0x14, 0x5e, 0x92, 0x0e, 0x2e, 0xca, 0x12, 0x77, 0xd2, 0x74,
	0x0b, 0xbb, 0xed, 0xab, 0x73, 0x38, 0x68, 0x2c, 0x1e, 0x7a, 0x11, 0x66, 0x42, 0x39, 0x6d, 0xbf,
	0x3e, 0xa7, 0x8d, 0x28, 0xc3, 0x1e, 0x8a, 0x63, 0x86, 0xb9, 0x46, 0x5d, 0x70, 0x97, 0x06, 0xc7,
	0x88, 0x63, 0xad, 0xbd, 0xac, 0xb4, 0x62, 0x9a, 0x61, 0x8f, 0x21, 0x32, 0x2c, 0xe4, 0xaf, 0x0d,
	0x29, 0x1d, 0xa6, 0xd8, 0x93, 0xa7, 0xe3, 0xf1, 0xc0, 0x43, 0x64, 0x5a, 0x00, 0x2e, 0xaa, 0xb8,
	0x60, 0xe3, 0xa8, 0xc8, 0xe7, 0xfa, 0xa2, 0xf6, 0x11, 0x43, 0x59, 0x86, 0x59, 0x91, 0xce, 0xf5,
	0x71, 0x9c, 0x21, 0x0f, 0x11, 0x42, 0x05, 0x12, 0x09, 0x25, 0xdc, 0x1b, 0x25, 0x43, 0x86, 0x44,
	0x11, 0xf8, 0xda, 0x39, 0x3d, 0x17, 0x48, 0x8c, 0x0b, 0xf7, 0xad, 0x09, 0x4a, 0x93, 0x18, 0x09,
	0xec, 0x15, 0x1f, 0x4a, 0xd1, 0xf8, 0xc9, 0x00, 0x95, 0x8f, 0x92, 0x54, 0x60, 0x06, 0xaf, 0x80,
	0x32, 0x41, 0x23, 0xec, 0x18, 0x75, 0x63, 0xa7, 0xea, 0xaf, 0x9c, 0xfa, 0x65, 0x66, 0xd6, 0x8d,
	0x40, 0x0a, 0xe1, 0xbb, 0xa0, 0x12, 0x51, 0x32, 0x48, 0x86, 0x8e, 0x59, 0x37, 0x76, 0x6a, 0xcd,
	0x2d, 0x57, 0x25, 0xec, 0x16, 0x09, 0xbb, 0x7d, 0x79, 0x1d, 0xdf, 0x74, 0x8c, 0xfd, 0xa5, 0x40,
	0x1b, 0xc3, 0xf7, 0xc1, 0x6a, 0x5e, 0xa3, 0x38, 0xd4, 0xce, 0x65, 0xe9, 0xbc, 0x79, 0xce, 0xb9,
	0x45, 0xa6, 0xfb, 0x4b, 0x41, 0x4d, 0xda, 0xb6, 0xa5, 0xa9, 0xbf, 0x06, 0x6a, 0xca, 0x29, 0xcc,
	0xa5, 0x77, 0xcb, 0x56, 0xc9, 0x2e, 0x37, 0x7e, 0x5f, 0x06, 0xb6, 0x4a, 0xb7, 0xfd, 0x10, 0x25,
	0xe4, 0x00, 0x89, 0xe8, 0x21, 0x3c, 0x02, 0x76, 0x8c, 0xb9, 0x48, 0x88, 0xbc, 0x79, 0x98, 0x51,
	0x26, 0x1c, 0x4b, 0x06, 0xba, 0x7a, 0x2e, 0xd0, 0xbd, 0x3b, 0x44, 0xec, 0x36, 0xef, 0xa3, 0x74,
	0x8c, 0xfd, 0xda, 0xa9, 0x6f, 0xbd, 0x5d, 0x71, 0x9e, 0x3c, 0x29, 0xed, 0x18, 0xc1, 0xc6, 0x19,
	0x88, 0x1e, 0x65, 0x02, 0xb6, 0xc0, 0x5a, 0xc6, 0xf0, 0x20, 0x39, 0x09, 0x65, 0x83, 0xb9, 0x53,
	0xaa, 0x97, 0x24, 0xe4, 0x1c, 0xdd, 0x72, 0x62, 0xb8, 0xed, 0x24, 0x66, 0x41, 0x6e, 0x14, 0xac,
	0x2a, 0x17, 0x79, 0xe0, 0xf0, 0x4d, 0xb0, 0xae, 0x49, 0x15, 0xf2, 0xf1, 0x60, 0x90, 0x9c, 0xc8,
	0xfb, 0x57, 0x83, 0x35, 0x2d, 0xed, 0x4b, 0x21, 0xfc, 0x00, 0x00, 0xa5, 0x0e, 0x53, 0x4c, 0x9c,
	0xe5, 0xe7, 0x67, 0x1e, 0x54, 0x95, 0x7d, 0x07, 0x13, 0x38, 0x04, 0x35, 0x4e, 0xc7, 0x2c, 0xc2,
	0xb2, 0x4c, 0xce, 0x6a, 0xdd, 0xd8, 0x59, 0x6f, 0x7e, 0xe8, 0x5e, 0x38, 0x13, 0xee, 0x62, 0xe9,
	0xdc, 0x36, 0x25, 0x04, 0x47, 0xf9, 0x9d, 0xfb, 0x12, 0xe4, 0x68, 0x9a, 0x61, 0xdf, 0x3a, 0xf5,
	0x97, 0xbf, 0x36, 0x4c, 0xdb, 0x08, 0x00, 0x9f, 0x49, 0x61, 0x17, 0x6c, 0xea, 0x40, 0xf3, 0x65,
	0xa9, 0xbc, 0x40, 0x59, 0xa0, 0xf2, 0xec, 0x9d, 0x2d, 0xce, 0x2e, 0x58, 0x2d, 0xf0, 0x28, 0x13,
	0xdc, 0x59, 0xa9, 0x97, 0x76, 0xd6, 0x7c, 0xfb, 0xd4, 0x5f, 0x7b, 0x6c, 0x80, 0xc6, 0xd3, 0xc6,
	0xe8, 0xeb, 0xe5, 0x3d, 0xe1, 0xf0, 0x06, 0x58, 0xe5, 0x98, 0x4d, 0x30, 0x0b, 0x73, 0x56, 0x72,
	0xa7, 0x56, 0x2f, 0xed, 0x54, 0x83, 0x9a, 0x92, 0x75, 0x73, 0x11, 0x7c, 0x07, 0x40, 0xc1, 0x10,
	0xe1, 0x39, 0x6a, 0x28, 0xab, 0x17, 0xd1, 0xd4, 0xa9, 0xca, 0xc2, 0xbf, 0x32, 0xd3, 0xf4, 0xb4,
	0x02, 0xee, 0x82, 0x4b, 0x28, 0xcb, 0xd2, 0x24, 0xd2, 0xe4, 0xd1, 0x72, 0xee, 0x00, 0x09, 0xbd,
	0x79, 0x46, 0x59, 0xf8, 0xf0, 0xc6, 0x3d, 0xb0, 0x79, 0x51, 0xe5, 0xe0, 0x0a, 0x28, 0xb5, 0xba,
	0x9f, 0xda, 0x4b, 0xf0, 0x26, 0x58, 0xee, 0x1c, 0xb6, 0x5b, 0x1d, 0xdb, 0xd8, 0xbe, 0xf2, 0xe7,
	0x77, 0x7f, 0x7f, 0xb3, 0x7c, 0x09, 0xbc, 0xda, 0x6f, 0x1d, 0xec, 0x85, 0x77, 0x7a, 0xe1, 0x61,
	0x10, 0x76, 0x0e, 0x0f, 0x7b, 0x7e, 0xab, 0xfd, 0x31, 0x5c, 0x05, 0xd6, 0xde, 0x83, 0xa3, 0xbd,
	0xa0, 0xdb, 0xea, 0xd8, 0xe6, 0xdd, 0xb2, 0x65, 0xd8, 0x66, 0xe3, 0xd7, 0x12, 0xa8, 0x9d, 0x69,
	0x14, 0xbc, 0x07, 0xe0, 0x40, 0x1e, 0xc3, 0x28, 0x3f, 0x87, 0xa3, 0xbc, 0x73, 0x72, 0x4a, 0x6b,
	0xcd, 0xb7, 0x5e, 0xb0, 0xd1, 0x81, 0x3d, 0x58, 0x9c, 0x9a, 0x0e, 0xa8, 0x89, 0x94, 0xe7, 0x83,
	0x29, 0xf0, 0x89, 0xd0, 0x63, 0xbd, 0x80, 0x97, 0x6f, 0x4d, 0xf7, 0x36, 0x7d, 0x44, 0xb8, 0x60,
	0x18, 0x8d, 0x8e, 0x52, 0xde, 0x56, 0xe6, 0xf9, 0x98, 0x07, 0x40, 0xcc, 0xce, 0xf0, 0x16, 0x58,
	0x51, 0x11, 0x8a, 0x39, 0xb9, 0xf6, 0xaf, 0x99, 0x05, 0x85, 0x35, 0xf4, 0xc1, 0xc6, 0x98, 0xe7,
	0x9c, 0xa2, 0x27, 0x53, 0x55, 0x7d, 0xbd, 0x24, 0xb6, 0xcf, 0x4d, 0x80, 0x4f, 0x69, 0xaa, 0xf8,
	0xbf, 0x36, 0xe6, 0xb8, 0x97, 0x7b, 0xc8, 0x96, 0xc0, 0x5b, 0xc0, 0x1a, 0x61, 0x81, 0x62, 0x24,
	0x90, 0x1e, 0x9f, 0x2b, 0x17, 0xd0, 0xf1, 0x40, 0x9b, 0x04, 0x33, 0x63, 0x78, 0x00, 0xec, 0xa7,
	0x5c, 0xe1, 0x34, 0xfa, 0x12, 0x0b, 0xa7, 0x22, 0x01, 0x1a, 0x17, 0x00, 0x1c, 0x15, 0xa6, 0x7d,
	0x69, 0x19, 0x6c, 0x88, 0x79, 0x01, 0x84, 0x7a, 0x83, 0xae, 0x48, 0xb2, 0xc9, 0xef, 0xc6, 0x0f,
	0x65, 0x70, 0xa3, 0xa3, 0x2f, 0xbf, 0xd8, 0x95, 0x1e, 0xc3, 0x71, 0xce, 0x2d, 0x0c, 0x3f, 0x03,
	0x16, 0x65, 0x73, 0x9d, 0x6d, 0x3d, 0xa3, 0x7e, 0xcf, 0xc5, 0x72, 0xe5, 0xb1, 0x8f, 0xc5, 0xfe,
	0x52, 0xb0, 0x42, 0x99, 0x6a, 0xf6, 0xe7, 0xa0, 0x8a, 0x48, 0xac, 0x03, 0x98, 0xff, 0x5d, 0x00,
	0x0b, 0x91, 0x58, 0x45, 0xf8, 0x04, 0x54, 0x09, 0x15, 0x3a, 0x42, 0x49, 0x46, 0x78, 0xef, 0x65,
	0x23, 0xe4, 0xc0, 0x84, 0x0a, 0x05, 0x7c, 0x33, 0x4f, 0x7d, 0xaa, 0x81, 0x73, 0x6a, 0x58, 0xf2,
	0x6d, 0xfa, 0xc2, 0xb4, 0x0c, 0x95, 0xc0, 0x54, 0xd9, 0x75, 0xc1, 0xe5, 0xc5, 0x57, 0x40, 0xad,
	0x28, 0x4d, 0x89, 0xcb, 0x3a, 0x9b, 0x7c, 0x4d, 0xba, 0x72, 0x97, 0xca, 0x45, 0xb4, 0xbf, 0x14,
	0x6c, 0x2e, 0xac, 0x7e, 0x29, 0xdf, 0x8e, 0x81, 0x55, 0x5c, 0x14, 0x3e, 0x00, 0xcb, 0x6c, 0x9c,
	0x62, 0xee, 0x18, 0x92, 0xdb, 0x2f, 0x7d, 0x31, 0xb9, 0x5a, 0x1f, 0x1b, 0xa6, 0x65, 0x06, 0x0a,
	0xd0, 0xaf, 0x81, 0x72, 0xfe, 0x01, 0x4b, 0x7f, 0xf9, 0x46, 0xe3, 0x5b, 0x13, 0xac, 0xcf, 0x63,
	0xfc, 0x2f, 0x8f, 0x72, 0xe9, 0x85, 0x1f, 0x65, 0x88, 0xc0, 0x86, 0xde, 0x45, 0x71, 0xc2, 0xd1,
	0x71, 0x8a, 0x63, 0x3d, 0xad, 0x2f, 0x5d, 0x92, 0x60, 0x5d, 0x01, 0xde, 0xd6, 0x78, 0x0b, 0xef,
	0xbe, 0xff, 0xbd, 0x21, 0xf7, 0xe7, 0x36, 0x74, 0x54, 0x00, 0xa5, 0x7b, 0x1a, 0x60, 0xb2, 0xfb,
	0xf3, 0x57, 0xbf, 0xfc, 0x56, 0x31, 0x6d, 0x03, 0xbc, 0x91, 0x50, 0x95, 0x85, 0x5c, 0x26, 0x17,
	0x27, 0xe4, 0x6f, 0x15, 0x19, 0xb5, 0x67, 0xff, 0x91, 0x72, 0x89, 0xf4, 0x8c, 0x1f, 0xcd, 0xad,
	0x3d, 0xe9, 0xd2, 0xca, 0x12, 0xf7, 0x7e, 0x73, 0x96, 0x7a, 0xb7, 0xff, 0xc7, 0x33, 0x35, 0xc7,
	0x15, 0x59, 0xad, 0xdd, 0x7f, 0x02, 0x00, 0x00, 0xff, 0xff, 0x7e, 0x9d, 0xc1, 0x3d, 0xb6, 0x0a,
	0x00, 0x00,
}