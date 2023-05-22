package runelite;

import runelite.plugin.ArnahPluginManager;
import runelite.plugin.config.ArnahPluginListPanel;
import net.runelite.client.ui.SplashScreen;

import javax.inject.Inject;

/**
 * @author Arnah
 * @since Nov 07, 2020
 */
public class HijackedClient{
	
	@Inject
	private ArnahPluginManager arnahPluginManager;
	@Inject
	private ArnahPluginListPanel pluginListPanel;
	
	public void start(){
		System.out.println("Start");
		new Thread(()->{
			while(SplashScreen.isOpen()){
				try{
					Thread.sleep(100);
				}catch(Exception ex){
					ex.printStackTrace();
				}
			}
			System.out.println("Splash Screen done");
			
			try{
				arnahPluginManager.loadExternalPlugins();
				pluginListPanel.init();
			}catch(Exception ex){
				ex.printStackTrace();
			}
		}).start();
	}
}