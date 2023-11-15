package epp

type EndpointConfig struct {
	DebugLog   bool `mapstructure:"debug_log"`
	Protectors []configProtector
	Endpoints  []configEndpoint
}

var (
	config         *EndpointConfig
	protectors     []Protector
	endpoints      []*Endpoint
	logger         Logger
	protectorIdMap map[string]int
	//endpointIdMap  map[string]int
)

// InitializeEndpointProtection loads all supported endpoint protectors from config
func InitializeEndpointProtection(cfg *EndpointConfig, lgr Logger) (err error) {
	logger = lgr
	if lgr == nil {
		logger = &DefaultLogger{}
	}

	config = cfg

	if err = initProtectors(cfg.Protectors); err != nil {
		return err
	}

	if err = initEndpoints(cfg.Endpoints); err != nil {
		return err
	}

	return nil
}
