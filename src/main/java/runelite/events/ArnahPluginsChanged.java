package runelite.events;

import runelite.plugin.ArnahPluginManifest;
import lombok.Value;

import java.util.List;

@Value
public class ArnahPluginsChanged{
	
	List<ArnahPluginManifest> loadedManifest;
}